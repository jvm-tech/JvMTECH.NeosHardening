<?php

namespace JvMTECH\NeosHardening\Service;

use Neos\Flow\Annotations as Flow;
use Neos\Error\Messages\Message;
use Neos\Flow\Aop\JoinPointInterface;
use Neos\Flow\Cache\CacheManager;
use Neos\Flow\Security\Exception\AuthenticationRequiredException;
use Neos\Flow\Validation\Exception as ValidationException;
use Neos\Neos\Domain\Service\UserService;

/**
 * @Flow\Aspect
 */
class LoginControllerAspect
{
    /**
     * @Flow\InjectConfiguration()
     * @var array
     */
    protected $settings;

    /**
     * @var CacheManager
     * @Flow\Inject
     */
    protected $cacheManager;

    /**
     * @var UserService
     * @Flow\Inject
     */
    protected $userService;

    /**
     * Store failed login attempts in cache and deactivate account after a certain number of failed attempts
     *
     * @Flow\Around("method(Neos\Neos\Controller\LoginController->onAuthenticationFailure()) && setting(JvMTECH.NeosHardening.checkFailedLogins)")
     * @param JoinPointInterface $joinPoint
     * @return string
     * @throws ValidationException
     */
    public function onAuthenticationFailureWithCheckFailedLogins(JoinPointInterface $joinPoint)
    {
        try {
            $username = $_POST['__authentication']['Neos']['Flow']['Security']['Authentication']['Token']['UsernamePassword']['username'];

            $user = $this->userService->getUser($username);
            if (!$user) {
                return $joinPoint->getAdviceChain()->proceed($joinPoint);
            }

            $cache = $this->cacheManager->getCache('JvMTECH_NeosHardening_FailedLogins');

            $failedLoginsCount = (int)$cache->get($username);
            $failedLoginsCount++;

            if ($failedLoginsCount > $this->settings['blockAfterFailedLogins']) {
                $this->userService->deactivateUser($user);
                throw new AuthenticationRequiredException('You have reached the maximum number of failed logins.');
            }

            $cache->set($username, $failedLoginsCount);
        } catch (\Exception $e) {
            $joinPoint->getProxy()->addFlashMessage(
                $e->getMessage(),
                'Error',
                Message::SEVERITY_ERROR,
                [],
                $e->getCode()
            );
        }

        return $joinPoint->getAdviceChain()->proceed($joinPoint);
    }

    /**
     * Reset failed login count on successful login
     *
     * @Flow\Around("method(Neos\Neos\Controller\LoginController->onAuthenticationSuccess()) && setting(JvMTECH.NeosHardening.checkFailedLogins)")
     * @param JoinPointInterface $joinPoint
     * @return string
     * @throws ValidationException
     */
    public function onAuthenticationSuccessWithCheckFailedLogins(JoinPointInterface $joinPoint)
    {
        try {
            $username = $_POST['__authentication']['Neos']['Flow']['Security']['Authentication']['Token']['UsernamePassword']['username'];

            $user = $this->userService->getUser($username);
            if (!$user) {
                return $joinPoint->getAdviceChain()->proceed($joinPoint);
            }

            $cache = $this->cacheManager->getCache('JvMTECH_NeosHardening_FailedLogins');
            $cache->set($username, 0);
        } catch (\Exception $e) {
            // ignore
        }

        return $joinPoint->getAdviceChain()->proceed($joinPoint);
    }

}
