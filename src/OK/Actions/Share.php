<?php


namespace OK\Actions;


use OK\Client\OKApiRequest;

class Share {

    /**
     * @var OKApiRequest
     */
    private $request;

    /**
     * Apps constructor.
     * @param OKApiRequest $request
     */
    public function __construct(OKApiRequest $request) {
        $this->request = $request;
    }

}