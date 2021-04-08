<?php

/**
 * This file is part of the pd-admin pd-user package.
 *
 * @package     pd-user
 * @license     LICENSE
 * @author      Matteo Rossi <matteo.rossi@thespacesm.com>
 * @link        https://github.com/appaydin/pd-user
 */

namespace Pd\UserBundle\Security;


use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Http\RememberMe\RememberMeServicesInterface;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;

use Pd\UserBundle\Model\UserInterface;

/**
 * Abstracts process for manually logging in a user.
 *
 * @author Johannes M. Schmitt <schmittjoh@gmail.com>
 */
class LoginManager implements LoginManagerInterface
{
    /**
     * @var TokenStorageInterface
     */
    private $tokenStorage;
    
    /**
     * @var UserCheckerInterface
     */
    private $userChecker;
    
    /**
     * @var SessionAuthenticationStrategyInterface
     */
    private $sessionStrategy;
    
    /**
     * @var RequestStack
     */
    private $requestStack;
    
    /**
     * @var RememberMeServicesInterface
     */
    private $rememberMeService;
    
    /**
     * LoginManager constructor.
     */
    public function __construct(TokenStorageInterface                   $tokenStorage,
                                UserCheckerInterface                    $userChecker,
                                SessionAuthenticationStrategyInterface  $sessionStrategy,
                                RequestStack                            $requestStack,
                                RememberMeServicesInterface             $rememberMeService = null
    ) {
        $this->tokenStorage     = $tokenStorage;
        $this->userChecker      = $userChecker;
        $this->sessionStrategy  = $sessionStrategy;
        $this->requestStack     = $requestStack;
        $this->rememberMeService= $rememberMeService;
    }
    
    /**
     * {@inheritdoc}
     */
    final public function loginUser($firewallName, UserInterface $user, Response $response = null)
    {
        $this->userChecker->checkPreAuth($user);
        
        $token                  = $this->createToken($firewallName, $user);
        $request                = $this->requestStack->getCurrentRequest();

        if (null !== $request) {
            $this->sessionStrategy->onAuthentication($request, $token);
            
            if (null !== $response && null !== $this->rememberMeService) {
                $this->rememberMeService->loginSuccess($request, $response, $token);
            }
        }
        
        $this->tokenStorage->setToken($token);
    }
    
    /**
     * @param string $firewall
     *
     * @return UsernamePasswordToken
     */
    protected function createToken($firewall, UserInterface $user)
    {
        return new UsernamePasswordToken($user, null, $firewall, $user->getRoles());
    }
}
