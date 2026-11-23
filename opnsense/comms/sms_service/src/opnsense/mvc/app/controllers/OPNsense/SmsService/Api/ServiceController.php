<?php

namespace OPNsense\SmsService\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\SmsService\General';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceTemplate = 'OPNsense/SmsService';
    protected static $internalServiceName = 'smsservice';
}
