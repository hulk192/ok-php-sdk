<?php

namespace OK\TransportClient\Curl;

use OK\TransportClient\TransportClient;
use OK\TransportClient\TransportClientResponse;
use OK\TransportClient\TransportRequestException;

class CurlHttpClient implements TransportClient {

    protected const HEADER_UPLOAD_CONTENT_TYPE = 'Content-Type: multipart/form-data';
    protected const QUESTION_MARK = '?';

    /**
     * @var array
     */
    protected $initial_opts;

    /**
     * CurlHttpClient constructor.
     * @param int $connection_timeout
     */
    public function __construct(int $connection_timeout) {
        $this->initial_opts = [
            CURLOPT_HEADER => true,
            CURLOPT_CONNECTTIMEOUT => $connection_timeout,
            CURLOPT_RETURNTRANSFER => true,
        ];
    }

    /**
     * Makes post request.
     *
     * @param string $url
     * @param array|null $payload
     *
     * @return TransportClientResponse
     * @throws TransportRequestException
     */
    public function post(string $url, ?array $payload = null): TransportClientResponse {
        return $this->sendRequest($url, [
            CURLOPT_POST => 1,
            CURLOPT_POSTFIELDS => $payload,
        ]);
    }

    /**
     * Makes get request.
     *
     * @param string $url
     * @param array|null $payload
     *
     * @return TransportClientResponse
     * @throws TransportRequestException
     */
    public function get(string $url, ?array $payload = null): TransportClientResponse {
        return $this->sendRequest($url . static::QUESTION_MARK . http_build_query($payload), []);
    }

    /**
     * Makes upload request.
     *
     * @param string $url
     * @param string $parameter_name
     * @param string $path
     *
     * @return TransportClientResponse
     * @throws TransportRequestException
     */
    public function upload(string $url, string $parameter_name, string $path): TransportClientResponse {
        $payload = [];
        $payload[$parameter_name] = (class_exists('CURLFile', false)) ?
            new \CURLFile($path) : '@' . $path;

        return $this->sendRequest($url, [
            CURLOPT_POST => 1,
            CURLOPT_HTTPHEADER => [
                static::HEADER_UPLOAD_CONTENT_TYPE,
            ],
            CURLOPT_POSTFIELDS => $payload,
        ]);
    }

    /**
     * Makes and sends request.
     *
     * @param string $url
     * @param array $opts
     *
     * @return mixed
     * @throws TransportRequestException
     */
    public function sendRequest(string $url, array $opts) {
        $curl = curl_init($url);

        curl_setopt_array($curl, $this->initial_opts + $opts);

        $response = curl_exec($curl);

        $curl_error_code = curl_errno($curl);
        $curl_error = curl_error($curl);

        curl_close($curl);

        if ($curl_error || $curl_error_code) {
            $error_msg = "Failed curl request. Curl error {$curl_error_code}";
            if ($curl_error) {
                $error_msg .= ": {$curl_error}";
            }

            $error_msg .= '.';

            throw new TransportRequestException($error_msg);
        }

        return $this->parseRawResponse($response);
    }

    /**
     * Breaks the raw response down into its headers, body and http status code.
     *
     * @param string $response
     *
     * @return TransportClientResponse
     */
    protected function parseRawResponse(string $response) {
        list($raw_headers, $body) = $this->extractResponseHeadersAndBody($response);
        list($http_status, $headers) = $this->getHeaders($raw_headers);
        return new TransportClientResponse($http_status, $headers, $body);
    }

    /**
     * Extracts the headers and the body into a two-part array.
     *
     * @param string $response
     *
     * @return array
     */
    protected function extractResponseHeadersAndBody(string $response) {
        $parts = explode("\r\n\r\n", $response);
        $raw_body = array_pop($parts);
        $raw_headers = implode("\r\n\r\n", $parts);

        return [trim($raw_headers), trim($raw_body)];
    }

    /**
     * Parses the raw headers and sets as an array.
     *
     * @param string The raw headers from the response.
     *
     * @return array
     */
    protected function getHeaders(string $raw_headers) {
        // Normalize line breaks
        $raw_headers = str_replace("\r\n", "\n", $raw_headers);

        // There will be multiple headers if a 301 was followed
        // or a proxy was followed, etc
        $header_collection = explode("\n\n", trim($raw_headers));
        // We just want the last response (at the end)
        $raw_header = array_pop($header_collection);

        $header_components = explode("\n", $raw_header);
        $result = [];
        $http_status = 0;
        foreach ($header_components as $line) {
            if (strpos($line, ': ') === false) {
                $http_status = $this->getHttpStatus($line);
            } else {
                list($key, $value) = explode(': ', $line, 2);
                $result[$key] = $value;
            }
        }

        return [$http_status, $result];
    }

    /**
     * Sets the HTTP response code from a raw header.
     *
     * @param string $raw_response_header
     *
     * @return int
     */
    protected function getHttpStatus(string $raw_response_header): int {
        $pieces = explode(' ', trim($raw_response_header));

        if (empty($pieces)) {
            return 0;
        }

        return (int)array_pop($pieces);
    }

}