<?php
namespace JvMTECH\NeosHardening\Mvc\Routing;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Routing\DynamicRoutePart;

class Router extends \Neos\Flow\Mvc\Routing\Router
{
    /**
     * @Flow\InjectConfiguration()
     * @var array
     */
    protected $settings;

    protected function initializeRoutesConfiguration()
    {
        if ($this->routesConfiguration === null) {
            parent::initializeRoutesConfiguration();

            $loginUri = $this->settings['loginUri'];
            if (!$loginUri) {
                return;
            }

            $this->routesConfiguration = array_map(function ($item) use ($loginUri) {
                $uriPatternReplaced = preg_replace('/^(neos)?($|\/)/', $loginUri . '$2', $item['uriPattern']);
                if ($uriPatternReplaced) {
                    $item['uriPattern'] = $uriPatternReplaced;
                }

                return $item;
            }, $this->routesConfiguration);
        }
    }

}
