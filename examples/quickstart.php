<?php

//Application ID: 512000617612.
//Публичный ключ приложения: CNINGOJGDIHBABABA.
//Секретный ключ приложения:  66C4B55D892C3CDFFD391848.

use OK\Client;

$client = new Client([
    'client_id' => 512000617612,
    'application_key' => 'CNINGOJGDIHBABABA',
    'application_secret_key' => '66C4B55D892C3CDFFD391848',
]);

$client->setAuthConfig('credentials.json');
