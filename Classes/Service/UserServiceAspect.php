<?php

namespace JvMTECH\NeosHardening\Service;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;
use Neos\Flow\Cache\CacheManager;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Flow\Security\Cryptography\HashService;
use Neos\Flow\Validation\Exception as ValidationException;
use Neos\Neos\Domain\Model\User;
use Neos\Neos\Service\UserService;

/**
 * @Flow\Aspect
 */
class UserServiceAspect
{
    /**
     * @Flow\InjectConfiguration()
     * @var array
     */
    protected array $settings;

    /**
     * @var CacheManager
     * @Flow\Inject
     */
    protected $cacheManager;

    /**
     * @Flow\Inject
     * @var HashService
     */
    protected $hashService;

    /**
     * @Flow\Inject
     * @var PersistenceManagerInterface
     */
    protected $persistenceManager;

    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

    /**
     *
     * @Flow\Around("method(Neos\Neos\Domain\Service\UserService->addUser()) && setting(JvMTECH.NeosHardening.checkPasswordStrengthOnAddUser)")
     * @param JoinPointInterface $joinPoint
     * @return string
     * @throws ValidationException
     */
    public function addUserWithCheckPasswordStrength(JoinPointInterface $joinPoint)
    {
        $password = $joinPoint->getMethodArgument('password');
        $this->checkPasswordStrength($password);

        $user = $joinPoint->getMethodArgument('user');
        $userObjectIdentifier = $this->persistenceManager->getIdentifierByObject($user);

        $cache = $this->cacheManager->getCache('JvMTECH_NeosHardening_ForcePasswordReset');
        $cache->set($userObjectIdentifier, true);

        return $joinPoint->getAdviceChain()->proceed($joinPoint);
    }

    /**
     *
     * @Flow\Around("method(Neos\Neos\Domain\Service\UserService->setUserPassword())")
     * @param JoinPointInterface $joinPoint
     * @return string
     * @throws ValidationException
     */
    public function setUserPasswordWithCheckPasswordStrengthAndHistory(JoinPointInterface $joinPoint)
    {
        $password = $joinPoint->getMethodArgument('password');

        /** @var User $user */
        $user = $joinPoint->getMethodArgument('user');
        $backendUser = $this->userService->getBackendUser();

        if ($this->settings['checkPasswordStrengthOnSetUserPassword']) {
            $this->checkPasswordStrength($password);
        }

        if ($this->settings['checkPasswordHistory']) {
            $this->checkPasswordHistory($user, $password);
        }

        if ($this->settings['forcePasswordResetAfterUpdate']) {
            $this->forcePasswordResetAfterUpdate($user, $backendUser);
        }

        return $joinPoint->getAdviceChain()->proceed($joinPoint);
    }

    protected function checkPasswordStrength($password)
    {
        if ($this->settings['passwordRequirements']['minLength'] && strlen($password) < $this->settings['passwordRequirements']['minLength']) {
            $this->throwPasswordRequirementsException('The password is too short.');
        }

        $uppercase = !$this->settings['passwordRequirements']['upperAndLowerCase'] ?: preg_match('@[A-Z]@', $password);
        $lowercase = !$this->settings['passwordRequirements']['upperAndLowerCase'] ?: preg_match('@[a-z]@', $password);
        $number    = !$this->settings['passwordRequirements']['numbers'] ?: preg_match('@[0-9]@', $password);
        $specialChars = !$this->settings['passwordRequirements']['specialChars'] ?: preg_match('@[^\w]@', $password);

        $hasConsecutiveLetters = false;
        if ((int)$this->settings['passwordRequirements']['maxConsecutiveLetters'] > 0) {
            $hasConsecutiveLetters = preg_match(
                sprintf(
                    '/[A-Za-z]{%d}/',
                    (int)$this->settings['passwordRequirements']['maxConsecutiveLetters'] + 1
                ),
                $password
            ) === 1;
        }

        $hasConsecutiveNumbers = false;
        if ((int)$this->settings['passwordRequirements']['maxConsecutiveNumbers'] > 0) {
            $hasConsecutiveNumbers = preg_match(
                sprintf(
                    '/[0-9]{%d}/',
                    (int)$this->settings['passwordRequirements']['maxConsecutiveNumbers'] + 1
                ),
                $password
            ) === 1;
        }

        if (!$uppercase || !$lowercase || !$number || !$specialChars || $hasConsecutiveLetters || $hasConsecutiveNumbers) {
            $this->throwPasswordRequirementsException('The password is too easy.');
        }
    }

    protected function checkPasswordHistory(User $user, $password)
    {
        $userObjectIdentifier = $this->persistenceManager->getIdentifierByObject($user);
        $hashedPassword = $this->hashService->hashPassword($password);

        $cache = $this->cacheManager->getCache('JvMTECH_NeosHardening_PasswordHistory');
        $history = $cache->get($userObjectIdentifier);

        if (!is_array($history)) {
            $history = [];
        }

        foreach ($history as $oldPassword) {
            if ($this->hashService->validatePassword($password, $oldPassword)) {
                throw new ValidationException('The password has already been used.');
            }
        }

        $history[] = $hashedPassword;
        $history = array_slice($history, (int)$this->settings['passwordHistoryLength'] * -1);

        $cache->set($userObjectIdentifier, $history);
    }

    protected function forcePasswordResetAfterUpdate(User $user, User $backendUser)
    {
        $userObjectIdentifier = $this->persistenceManager->getIdentifierByObject($user);
        $backendUserObjectIdentifier = $this->persistenceManager->getIdentifierByObject($backendUser);

        $cache = $this->cacheManager->getCache('JvMTECH_NeosHardening_ForcePasswordReset');

        if ($userObjectIdentifier === $backendUserObjectIdentifier) {
            $cache->remove($userObjectIdentifier);
        } else {
            $cache->set($userObjectIdentifier, true);
        }
    }

    protected function throwPasswordRequirementsException($message)
    {
        $requiredTexts = [];
        foreach ($this->settings['passwordRequirements'] as $passwordRequirementKey => $passwordRequirementValue) {
            if ($passwordRequirementValue === true) {
                $requiredTexts[] = ucfirst($passwordRequirementKey);
            } elseif ($passwordRequirementValue > 0) {
                if (substr($passwordRequirementKey, 0, 3) === 'min') {
                    $compareStr = ' >= ';
                } else {
                    $compareStr = ' <= ';
                }
                $requiredTexts[] = ucfirst($passwordRequirementKey) . $compareStr . $passwordRequirementValue;
            }
        }

        throw new ValidationException($message . ' Required is: ' . implode(', ', $requiredTexts));
    }
}
