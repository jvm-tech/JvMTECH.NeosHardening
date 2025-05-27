<?php
declare(strict_types=1);

namespace JvMTECH\NeosHardening\Mvc\Routing;

use Neos\Flow\Configuration\ConfigurationManager;
use Neos\Flow\Mvc\Routing\Route;
use Neos\Flow\Mvc\Routing\Routes;
use Neos\Flow\Mvc\Routing\RoutesProviderFactoryInterface;
use Neos\Flow\Mvc\Routing\RoutesProviderInterface;
use Neos\Flow\ObjectManagement\ObjectManagerInterface;

class ConfigurationRoutesProvider implements RoutesProviderInterface
{
    public function __construct(
        private ConfigurationManager $configurationManager,
        private ObjectManagerInterface $objectManager,
    ) {
    }

    public function getRoutes(): Routes
    {
        $configuration = $this->configurationManager->getConfiguration(ConfigurationManager::CONFIGURATION_TYPE_SETTINGS, 'JvMTECH.NeosHardening');
        $loginUri = $configuration['loginUri'];
        $routes = [];
        foreach ($this->configurationManager->getConfiguration(ConfigurationManager::CONFIGURATION_TYPE_ROUTES) as $routeConfiguration) {
            if (isset($routeConfiguration['providerFactory'])) {
                $providerFactory = $this->objectManager->get($routeConfiguration['providerFactory']);
                if (!$providerFactory instanceof RoutesProviderFactoryInterface) {
                    throw new \InvalidArgumentException(sprintf('The configured route providerFactory "%s" does not implement the "%s"', $routeConfiguration['providerFactory'], RoutesProviderFactoryInterface::class), 1710784630);
                }
                $provider = $providerFactory->createRoutesProvider($routeConfiguration['providerOptions'] ?? []);
                foreach ($provider->getRoutes() as $route) {
                    $routes[] = $route;
                }
            } else {
                if (empty($loginUri)) {

                }
                $uriPatternReplaced = preg_replace('/^(neos)?($|\/)/', $loginUri . '$2', $routeConfiguration['uriPattern']);
                if ($uriPatternReplaced) {
                    $routeConfiguration['uriPattern'] = $uriPatternReplaced;
                }
                $routes[] = Route::fromConfiguration($routeConfiguration);
            }
        }
        return Routes::create(...$routes);
    }
}
