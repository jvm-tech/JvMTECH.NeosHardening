<?php

namespace JvMTECH\NeosHardening\Service;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;

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
     *
     * @Flow\Around("method(Neos\Neos\Domain\Service\UserService->addUser()) && setting(JvMTECH.NeosHardening.checkPasswordStrengthOnAddUser)")
     * @param JoinPointInterface $joinPoint
     * @return string
     */
    public function addUserWithCheckPasswordStrength(JoinPointInterface $joinPoint)
    {
        $password = $joinPoint->getMethodArgument('password');
        $this->checkPasswordStrength($password);

        return $joinPoint->getAdviceChain()->proceed($joinPoint);
    }

    /**
     *
     * @Flow\Around("method(Neos\Neos\Domain\Service\UserService->setUserPassword()) && setting(JvMTECH.NeosHardening.checkPasswordStrengthOnSetUserPassword)")
     * @param JoinPointInterface $joinPoint
     * @return string
     */
    public function setUserPasswordWithCheckPasswordStrength(JoinPointInterface $joinPoint)
    {
        $password = $joinPoint->getMethodArgument('password');
        $this->checkPasswordStrength($password);

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
                    '/[A-Za-z]{%d}/',
                    (int)$this->settings['passwordRequirements']['maxConsecutiveNumbers'] + 1
                ),
                $password
            ) === 1;
        }

        if (!$uppercase || !$lowercase || !$number || !$specialChars || $hasConsecutiveLetters || $hasConsecutiveNumbers) {
            $this->throwPasswordRequirementsException('The password is too easy.');
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

        throw new \Exception($message . ' Required is: ' . implode(', ', $requiredTexts));
    }
}
