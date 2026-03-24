/*
 * Copyright (c) 2025 Minki Technology (https://minki.cc)
 * Licensed under the MIT License.
 */

<template>
  <div class="chart-wrapper">
    <svg
      v-if="hasData"
      class="chart-svg"
      viewBox="0 0 900 320"
      role="img"
      :aria-label="t('activity.chart.title')"
      preserveAspectRatio="xMidYMid meet"
    >
      <text class="chart-title" :x="viewBox.width / 2" y="22" text-anchor="middle">
        {{ t('activity.chart.title') }}
      </text>

      <g class="grid">
        <template v-for="tick in yTicks" :key="tick.value">
          <line
            class="grid-line"
            :x1="padding.left"
            :x2="padding.left + chartWidth"
            :y1="tick.y"
            :y2="tick.y"
          />
          <text
            class="y-axis-label"
            :x="padding.left - 10"
            :y="tick.y + 4"
            text-anchor="end"
          >
            {{ tick.label }}
          </text>
        </template>
      </g>

      <g class="axes">
        <line
          class="axis-line"
          :x1="padding.left"
          :x2="padding.left"
          :y1="padding.top"
          :y2="padding.top + chartHeight"
        />
        <line
          class="axis-line"
          :x1="padding.left"
          :x2="padding.left + chartWidth"
          :y1="padding.top + chartHeight"
          :y2="padding.top + chartHeight"
        />
      </g>

      <g class="legend">
        <g
          v-for="(series, index) in seriesList"
          :key="series.key"
          :transform="`translate(${padding.left + index * 170}, ${padding.top - 26})`"
        >
          <line
            :stroke="series.color"
            stroke-width="3"
            x1="0"
            x2="20"
            y1="0"
            y2="0"
            stroke-linecap="round"
          />
          <text class="legend-label" x="28" y="4">{{ series.label }}</text>
        </g>
      </g>

      <g class="areas">
        <polygon
          v-for="series in seriesList"
          :key="`${series.key}-area`"
          :points="series.areaPoints"
          :fill="series.fill"
        />
      </g>

      <g class="lines">
        <polyline
          v-for="series in seriesList"
          :key="`${series.key}-line`"
          :points="series.linePoints"
          :stroke="series.color"
          stroke-width="3"
          fill="none"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </g>

      <g class="points">
        <template v-for="series in seriesList" :key="`${series.key}-points`">
          <circle
            v-for="point in series.points"
            :key="`${series.key}-${point.index}`"
            class="data-point"
            :cx="point.x"
            :cy="point.y"
            r="4"
            :fill="series.color"
          >
            <title>{{ point.tooltip }}</title>
          </circle>
        </template>
      </g>

      <g class="x-axis">
        <template v-for="label in xAxisLabels" :key="label.index">
          <line
            class="tick-line"
            :x1="label.x"
            :x2="label.x"
            :y1="padding.top + chartHeight"
            :y2="padding.top + chartHeight + 6"
          />
          <text
            class="x-axis-label"
            :x="label.x"
            :y="padding.top + chartHeight + 22"
            text-anchor="middle"
          >
            {{ label.text }}
          </text>
        </template>
      </g>

      <text
        class="axis-title"
        :x="padding.left + chartWidth / 2"
        :y="viewBox.height - 10"
        text-anchor="middle"
      >
        {{ t('activity.chart.date') }}
      </text>
      <text
        class="axis-title"
        :x="20"
        :y="padding.top + chartHeight / 2"
        text-anchor="middle"
        :transform="`rotate(-90, 20, ${padding.top + chartHeight / 2})`"
      >
        {{ t('activity.chart.count') }}
      </text>
    </svg>

    <div v-else class="empty-state">
      {{ t('common.no_data') }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, PropType } from 'vue'
import { ActivityData } from '@/api'
import { useI18n } from 'vue-i18n'

type ChartPoint = {
  index: number
  x: number
  y: number
  tooltip: string
}

type Series = {
  key: string
  label: string
  color: string
  fill: string
  points: ChartPoint[]
  linePoints: string
  areaPoints: string
}

const props = defineProps({
  data: {
    type: Array as PropType<ActivityData[]>,
    required: true
  }
})

const { t } = useI18n()

const viewBox = {
  width: 900,
  height: 320
}

const padding = {
  top: 52,
  right: 28,
  bottom: 48,
  left: 72
}

const chartWidth = viewBox.width - padding.left - padding.right
const chartHeight = viewBox.height - padding.top - padding.bottom
const hasData = computed(() => props.data.length > 0)

const niceMaxValue = (value: number) => {
  if (value <= 0) {
    return 1
  }

  const magnitude = 10 ** Math.floor(Math.log10(value))
  const normalized = value / magnitude

  if (normalized <= 1) return magnitude
  if (normalized <= 2) return 2 * magnitude
  if (normalized <= 5) return 5 * magnitude
  return 10 * magnitude
}

const formatTickValue = (value: number) => {
  if (value >= 10) {
    return String(Math.round(value))
  }

  const rounded = Math.round(value * 10) / 10
  return Number.isInteger(rounded) ? String(rounded) : rounded.toFixed(1)
}

const maxValue = computed(() => {
  const rawMax = props.data.reduce((currentMax, item) => {
    return Math.max(
      currentMax,
      item.new_users,
      item.active_users,
      item.login_attempts
    )
  }, 0)

  return niceMaxValue(rawMax)
})

const getX = (index: number) => {
  if (props.data.length <= 1) {
    return padding.left + chartWidth / 2
  }

  return padding.left + (chartWidth / (props.data.length - 1)) * index
}

const getY = (value: number) => {
  const ratio = value / maxValue.value
  return padding.top + chartHeight - ratio * chartHeight
}

const buildSeries = (
  key: 'new_users' | 'active_users' | 'login_attempts',
  label: string,
  color: string,
  fill: string
): Series => {
  const points = props.data.map((item, index) => {
    const value = item[key]
    return {
      index,
      x: getX(index),
      y: getY(value),
      tooltip: `${item.date} · ${label}: ${value}`
    }
  })

  const linePoints = points.map((point) => `${point.x},${point.y}`).join(' ')
  const areaPoints = [
    `${padding.left},${padding.top + chartHeight}`,
    linePoints,
    `${padding.left + chartWidth},${padding.top + chartHeight}`
  ].join(' ')

  return {
    key,
    label,
    color,
    fill,
    points,
    linePoints,
    areaPoints
  }
}

const seriesList = computed(() => [
  buildSeries(
    'new_users',
    t('activity.chart.new_users'),
    '#67C23A',
    'rgba(103, 194, 58, 0.12)'
  ),
  buildSeries(
    'active_users',
    t('activity.chart.active_users'),
    '#409EFF',
    'rgba(64, 158, 255, 0.10)'
  ),
  buildSeries(
    'login_attempts',
    t('activity.chart.login_attempts'),
    '#E6A23C',
    'rgba(230, 162, 60, 0.10)'
  )
])

const yTicks = computed(() => {
  const tickCount = 5
  return Array.from({ length: tickCount }, (_, index) => {
    const value = maxValue.value - (maxValue.value / (tickCount - 1)) * index
    return {
      value,
      label: formatTickValue(value),
      y: padding.top + (chartHeight / (tickCount - 1)) * index
    }
  })
})

const xAxisLabels = computed(() => {
  if (props.data.length === 0) {
    return []
  }

  const maxLabels = 6
  const labelIndexes = new Set<number>()
  const step = props.data.length <= maxLabels ? 1 : Math.ceil((props.data.length - 1) / (maxLabels - 1))

  for (let index = 0; index < props.data.length; index += step) {
    labelIndexes.add(index)
  }

  labelIndexes.add(props.data.length - 1)

  return [...labelIndexes]
    .sort((left, right) => left - right)
    .map((index) => ({
      index,
      x: getX(index),
      text: props.data[index].date
    }))
})
</script>

<style lang="scss" scoped>
.chart-wrapper {
  width: 100%;
  height: 100%;
  min-height: 320px;
}

.chart-svg {
  width: 100%;
  height: 100%;
  overflow: visible;
}

.chart-title {
  fill: #303133;
  font-size: 15px;
  font-weight: 600;
}

.grid-line,
.tick-line {
  stroke: #e4e7ed;
  stroke-width: 1;
}

.axis-line {
  stroke: #c0c4cc;
  stroke-width: 1.2;
}

.legend-label,
.x-axis-label,
.y-axis-label,
.axis-title {
  fill: #606266;
  font-size: 12px;
}

.axis-title {
  font-weight: 500;
}

.data-point {
  transition: r 0.15s ease;
}

.data-point:hover {
  r: 6;
}

.empty-state {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  color: #909399;
  font-size: 14px;
}
</style>
