<?php
namespace JvMTECH\NeosHardening\Service;

use Neos\Flow\Annotations as Flow;
use Neos\Flow\Aop\JoinPointInterface;

/**
 * @Flow\Aspect
 */
class UserServiceAspect {

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

        if(!$uppercase || !$lowercase || !$number || !$specialChars || strlen($password) < 8) {
            $this->throwPasswordRequirementsException('The password is too easy.');
        }

    }

    protected function throwPasswordRequirementsException($message)
    {
        $requiredTexts = [];
        foreach ($this->settings['passwordRequirements'] as $passwordRequirementKey => $passwordRequirementValue) {
            if ($passwordRequirementKey === 'minLength' && $passwordRequirementValue > 0) {
                $requiredTexts[] = 'MinLength >= ' . $passwordRequirementValue;
            } elseif ($passwordRequirementValue === true) {
                $requiredTexts[] = ucfirst($passwordRequirementKey);
            }
        }

        throw new \Exception($message . ' Required is: ' . implode(', ', $requiredTexts));
    }

}
