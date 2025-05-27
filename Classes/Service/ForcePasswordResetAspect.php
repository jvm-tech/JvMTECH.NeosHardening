<?php

namespace JvMTECH\NeosHardening\Service;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;
use Neos\Flow\Cache\CacheManager;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Validation\Exception as ValidationException;
use Neos\Neos\Service\UserService;

#[Flow\Aspect]
class ForcePasswordResetAspect
{
    #[Flow\InjectConfiguration]
    protected array $settings;

    #[Flow\Inject]
    protected UserService $userService;

    #[Flow\Inject]
    protected CacheManager $cacheManager;

    #[Flow\Inject]
    protected PersistenceManagerInterface $persistenceManager;

    /**
     *
     * @Flow\Around("method(Neos\Neos\Ui\Controller\BackendController->indexAction()) && setting(JvMTECH.NeosHardening.forcePasswordResetAfterUpdate)")
     * @param JoinPointInterface $joinPoint
     * @return string
     * @throws ValidationException
     */
    public function forcePasswordResetInContentControllerIndex(JoinPointInterface $joinPoint): string
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
    public function forcePasswordResetInBackendControllerIndex(JoinPointInterface $joinPoint): string
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
