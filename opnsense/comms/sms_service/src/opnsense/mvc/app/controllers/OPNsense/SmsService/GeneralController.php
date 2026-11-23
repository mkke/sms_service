<?php

namespace OPNsense\SmsService;

use OPNsense\Base\IndexController;

class GeneralController extends IndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/SmsService/general');
        $this->view->generalForm = $this->getForm('general');
    }
}
