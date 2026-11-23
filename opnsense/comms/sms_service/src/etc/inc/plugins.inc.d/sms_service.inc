<?php

function sms_service_services()
{
    $services = [];
    $mdl = new \OPNsense\SmsService\General();

    if ((string)$mdl->enabled != '1') {
        return $services;
    }

    $services[] = [
        'description' => gettext('SMS Gateway'),
        'configd' => [
            'restart' => ['smsservice restart'],
            'start' => ['smsservice start'],
            'stop' => ['smsservice stop'],
        ],
        'name' => 'sms_service',
        'pidfile' => '/var/run/sms_service.pid',
    ];

    return $services;
}
