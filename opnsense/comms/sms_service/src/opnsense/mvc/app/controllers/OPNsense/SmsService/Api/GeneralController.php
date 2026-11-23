<?php

namespace OPNsense\SmsService\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class GeneralController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'general';
    protected static $internalModelClass = 'OPNsense\SmsService\General';
}
