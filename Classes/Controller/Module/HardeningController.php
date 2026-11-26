<?php

namespace JvMTECH\NeosHardening\Controller\Module;

use Neos\Error\Messages\Message;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Cache\CacheManager;
use Neos\Flow\I18n\Translator;
use Neos\Flow\Persistence\PersistenceManagerInterface;
use Neos\Neos\Controller\Module\AbstractModuleController;
use Neos\Neos\Domain\Model\User;
use Neos\Neos\Domain\Service\UserService;

class HardeningController extends AbstractModuleController
{
    protected const CACHE_FAILED_LOGINS = 'JvMTECH_NeosHardening_FailedLogins';
    protected const CACHE_FORCE_PASSWORD_RESET = 'JvMTECH_NeosHardening_ForcePasswordReset';

    #[Flow\InjectConfiguration]
    protected array $hardeningSettings;

    #[Flow\InjectConfiguration(path: 'http.applicationToken', package: 'Neos.Flow')]
    protected string $applicationToken;

    #[Flow\Inject]
    protected UserService $userService;

    #[Flow\Inject]
    protected CacheManager $cacheManager;

    #[Flow\Inject]
    protected Translator $translator;

    #[Flow\Inject]
    protected PersistenceManagerInterface $persistenceManager;

    public function indexAction(): void
    {
        $failedLoginsCache = $this->cacheManager->getCache(self::CACHE_FAILED_LOGINS);
        $forcePasswordResetCache = $this->cacheManager->getCache(self::CACHE_FORCE_PASSWORD_RESET);
        $currentUser = $this->userService->getCurrentUser();

        $rows = [];
        /** @var User $user */
        foreach ($this->userService->getUsers() as $user) {
            $userIdentifier = $this->persistenceManager->getIdentifierByObject($user);
            $rows[] = [
                'user' => $user,
                'isCurrentUser' => $currentUser !== null && $userIdentifier === $this->persistenceManager->getIdentifierByObject($currentUser),
                'isActive' => $user->isActive(),
                'failedLogins' => (int)$failedLoginsCache->get($userIdentifier),
                'passwordResetRequired' => (bool)$forcePasswordResetCache->get($userIdentifier),
            ];
        }

        $this->view->assignMultiple([
            'activeTab' => 'users',
            'disabledCount' => $this->countDisabled($this->getSecurityChecks()),
            'rows' => $rows,
            'hardeningSettings' => $this->hardeningSettings,
        ]);
    }

    public function securityChecksAction(): void
    {
        $checks = $this->getSecurityChecks();
        // Disabled features first; usort is stable, so the order within each group is kept
        usort($checks, static fn (array $a, array $b) => $a['enabled'] <=> $b['enabled']);

        $this->view->assignMultiple([
            'activeTab' => 'checks',
            'disabledCount' => $this->countDisabled($checks),
            'checks' => $checks,
        ]);
    }

    /**
     * Activate all accounts of the user and reset its failed login counter
     */
    public function activateAction(User $user): void
    {
        $this->userService->activateUser($user);
        $this->cacheManager->getCache(self::CACHE_FAILED_LOGINS)->remove($this->getUserIdentifier($user));

        $this->addFlashMessage($this->translate('flash.activated', [$user->getLabel()]));
        $this->redirect('index');
    }

    /**
     * Deactivate all accounts of the user; Neos also destroys all of the user's active sessions
     */
    public function deactivateAction(User $user): void
    {
        if ($this->isCurrentUser($user)) {
            $this->addFlashMessage($this->translate('flash.cannotDeactivateYourself'), '', Message::SEVERITY_ERROR);
            $this->redirect('index');
        }

        $this->userService->deactivateUser($user);

        $this->addFlashMessage($this->translate('flash.deactivated', [$user->getLabel()]));
        $this->redirect('index');
    }

    /**
     * Require the user to change the password on next backend access
     */
    public function requirePasswordResetAction(User $user): void
    {
        if (empty($this->hardeningSettings['forcePasswordResetAfterUpdate'])) {
            $this->addFlashMessage($this->translate('flash.passwordResetDisabled', ['JvMTECH.NeosHardening.forcePasswordResetAfterUpdate']), '', Message::SEVERITY_ERROR);
            $this->redirect('index');
        }

        $this->cacheManager->getCache(self::CACHE_FORCE_PASSWORD_RESET)->set($this->getUserIdentifier($user), true);

        $this->addFlashMessage($this->translate('flash.passwordResetRequired', [$user->getLabel()]));
        $this->redirect('index');
    }

    /**
     * Remove the password change requirement of the user
     */
    public function clearPasswordResetAction(User $user): void
    {
        $this->cacheManager->getCache(self::CACHE_FORCE_PASSWORD_RESET)->remove($this->getUserIdentifier($user));

        $this->addFlashMessage($this->translate('flash.passwordResetCleared', [$user->getLabel()]));
        $this->redirect('index');
    }

    /**
     * One entry per feature of this package, with all settings belonging to it
     *
     * @return array<int, array{title: string, enabled: bool, values: string[], settings: string[]}>
     */
    protected function getSecurityChecks(): array
    {
        $settings = $this->hardeningSettings;

        $loginUri = (string)($settings['loginUri'] ?? '');
        $loginUriRegex = (string)($settings['loginUriRegex'] ?? '');
        $allowedIPs = array_merge($settings['allowedIPs']['IPv4'] ?? [], $settings['allowedIPs']['IPv6'] ?? []);
        $serverParamsIpKeys = $settings['allowedIPs']['serverParamsIpKeys'] ?? [];
        ksort($serverParamsIpKeys);
        $passwordRequirements = $this->describePasswordRequirements($settings['passwordRequirements'] ?? []);

        return [
            $this->check(
                $this->translate('checks.applicationToken.title'),
                $this->applicationToken === 'ApplicationName',
                [$this->translate('checks.applicationToken.value', [$this->applicationToken])],
                ['Neos.Flow.http.applicationToken'],
                false
            ),
            $this->check(
                $this->translate('checks.loginUri.title'),
                $loginUri !== '' && $loginUri !== 'neos',
                ['/' . ($loginUri ?: 'neos')],
                ['loginUri']
            ),
            $this->check(
                $this->translate('checks.allowedIPs.title'),
                $allowedIPs !== [],
                [
                    $allowedIPs !== [] ? $this->translate('checks.allowedIPs.allowed', [implode(', ', $allowedIPs)]) : $this->translate('checks.allowedIPs.any'),
                    $this->translate('checks.allowedIPs.serverParams', [implode(', ', $serverParamsIpKeys)]),
                    $this->translate('checks.allowedIPs.regex', [$loginUriRegex ?: sprintf('/^(%s)?($|\/)/', $loginUri ?: 'neos')]),
                ],
                ['allowedIPs.IPv4', 'allowedIPs.IPv6', 'allowedIPs.serverParamsIpKeys', 'loginUriRegex']
            ),
            $this->check(
                $this->translate('checks.passwordStrengthOnAddUser.title'),
                !empty($settings['checkPasswordStrengthOnAddUser']),
                [$passwordRequirements],
                ['checkPasswordStrengthOnAddUser', 'passwordRequirements']
            ),
            $this->check(
                $this->translate('checks.passwordStrengthOnSetUserPassword.title'),
                !empty($settings['checkPasswordStrengthOnSetUserPassword']),
                [$passwordRequirements],
                ['checkPasswordStrengthOnSetUserPassword', 'passwordRequirements']
            ),
            $this->check(
                $this->translate('checks.failedLogins.title'),
                !empty($settings['checkFailedLogins']),
                [$this->translate('checks.failedLogins.value', [(int)($settings['blockAfterFailedLogins'] ?? 0)])],
                ['checkFailedLogins', 'blockAfterFailedLogins']
            ),
            $this->check(
                $this->translate('checks.passwordHistory.title'),
                !empty($settings['checkPasswordHistory']),
                [$this->translate('checks.passwordHistory.value', [(int)($settings['passwordHistoryLength'] ?? 0)])],
                ['checkPasswordHistory', 'passwordHistoryLength']
            ),
            $this->check(
                $this->translate('checks.forcePasswordReset.title'),
                !empty($settings['forcePasswordResetAfterUpdate']),
                [],
                ['forcePasswordResetAfterUpdate']
            ),
        ];
    }

    protected function describePasswordRequirements(array $requirements): string
    {
        $parts = [];
        if (!empty($requirements['minLength'])) {
            $parts[] = $this->translate('passwordRequirements.minLength', [(int)$requirements['minLength']]);
        }
        if (!empty($requirements['upperAndLowerCase'])) {
            $parts[] = $this->translate('passwordRequirements.upperAndLowerCase');
        }
        if (!empty($requirements['numbers'])) {
            $parts[] = $this->translate('passwordRequirements.numbers');
        }
        if (!empty($requirements['specialChars'])) {
            $parts[] = $this->translate('passwordRequirements.specialChars');
        }
        if (!empty($requirements['maxConsecutiveLetters'])) {
            $parts[] = $this->translate('passwordRequirements.maxConsecutiveLetters', [(int)$requirements['maxConsecutiveLetters']]);
        }
        if (!empty($requirements['maxConsecutiveNumbers'])) {
            $parts[] = $this->translate('passwordRequirements.maxConsecutiveNumbers', [(int)$requirements['maxConsecutiveNumbers']]);
        }

        return implode(', ', $parts);
    }

    protected function countDisabled(array $checks): int
    {
        return count(array_filter($checks, static fn (array $check) => !$check['enabled']));
    }

    /**
     * @param string[] $values
     * @param string[] $settingNames Relative to JvMTECH.NeosHardening unless $prefixSettings is false
     */
    protected function check(string $title, bool $enabled, array $values, array $settingNames, bool $prefixSettings = true): array
    {
        return [
            'title' => $title,
            'enabled' => $enabled,
            'values' => array_values(array_filter($values, static fn (string $value) => $value !== '')),
            'settings' => array_map(
                static fn (string $settingName) => ($prefixSettings ? 'JvMTECH.NeosHardening.' : '') . $settingName,
                $settingNames
            ),
        ];
    }

    protected function translate(string $id, array $arguments = []): string
    {
        // The locale is set to the backend user's interface language by AbstractModuleController
        return (string)$this->translator->translateById($id, $arguments, null, null, 'Modules', 'JvMTECH.NeosHardening');
    }

    protected function getUserIdentifier(User $user): string
    {
        return (string)$this->persistenceManager->getIdentifierByObject($user);
    }

    protected function isCurrentUser(User $user): bool
    {
        $currentUser = $this->userService->getCurrentUser();

        return $currentUser !== null && $this->getUserIdentifier($currentUser) === $this->getUserIdentifier($user);
    }
}
