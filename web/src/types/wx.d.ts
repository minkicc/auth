/*
 * Copyright (c) 2025 Auth Contributors (https://example.com)
 * Licensed under the MIT License.
 */

declare namespace wx {
    interface LoginResult {
        code: string;
        errMsg: string;
    }

    function login(): Promise<LoginResult>;
} 