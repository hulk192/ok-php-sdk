<?php


namespace OK\Actions;


use OK\Client\OKApiRequest;

class VkNotifications {

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

    public function sendMessage(string $access_token, array $params = []) {
        $this->request->post('vk.notifications.sendMessage', $access_token, $params);
    }

}