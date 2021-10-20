<?php

namespace OK\Auth;

interface GetQuotaProjectInterface
{

    const X_GOOG_USER_PROJECT_HEADER = 'X-Goog-User-Project';

    /**
     * Get the quota project used for this API request
     *
     * @return string|null
     */
    public function getQuotaProject();
}
