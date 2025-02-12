<?php

namespace JvMTECH\NeosHardening\Service;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;
use Neos\Flow\Cache\CacheManager;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Validation\Exception as ValidationException;
use Neos\Neos\Service\UserService;

/**
 * @Flow\Aspect
 */
class ForcePasswordResetAspect
{
    /**
     * @Flow\InjectConfiguration()
     * @var array
     */
    protected array $settings;

    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

    /**
     * @var CacheManager
     * @Flow\Inject
     */
    protected $cacheManager;

    /**
     * @Flow\Inject
     * @var PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     *
     * @Flow\Around("method(Neos\Neos\Ui\Controller\BackendController->indexAction()) && setting(JvMTECH.NeosHardening.forcePasswordResetAfterUpdate)")
     * @param JoinPointInterface $joinPoint
     * @return string
     * @throws ValidationException
     */
    public function forcePasswordResetInContentControllerIndex(JoinPointInterface $joinPoint)
    {
        $user = $this->userService->getBackendUser();
        $userObjectIdentifier = $this->persistenceManager->getIdentifierByObject($user);

        $cache = $this->cacheManager->getCache('JvMTECH_NeosHardening_ForcePasswordReset');
        if ($cache->get($userObjectIdentifier)) {
            header('Location: /neos/user/usersettings');
            exit();
        }

        return $joinPoint->getAdviceChain()->proceed($joinPoint);
    }

    /**
     *
     * @Flow\Around("method(Neos\Neos\Controller\Backend\ModuleController->indexAction()) && setting(JvMTECH.NeosHardening.forcePasswordResetAfterUpdate)")
     * @param JoinPointInterface $joinPoint
     * @return string
     * @throws ValidationException
     */
    public function forcePasswordResetInBackendControllerIndex(JoinPointInterface $joinPoint)
    {
        $user = $this->userService->getBackendUser();
        $userObjectIdentifier = $this->persistenceManager->getIdentifierByObject($user);

        $cache = $this->cacheManager->getCache('JvMTECH_NeosHardening_ForcePasswordReset');
        if ($cache->get($userObjectIdentifier) && mb_strpos($_SERVER['REQUEST_URI'], 'neos/user/usersettings') === false) {
            header('Location: /neos/user/usersettings');
            exit();
        }

        return $joinPoint->getAdviceChain()->proceed($joinPoint);
    }
}
