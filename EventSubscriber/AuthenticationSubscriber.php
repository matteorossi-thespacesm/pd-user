<?php

/**
 * This file is part of the pd-admin pd-user package.
 *
 * @package     pd-user
 * @license     LICENSE
 * @author      Matteo Rossi <matteo.rossi@thespacesm.com>
 * @link        https://github.com/appaydin/pd-user
 */

namespace Pd\UserBundle\Listener;

use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;

use Pd\UserBundle\Event\UserEvent;
use Pd\UserBundle\Security\LoginManagerInterface;

class AuthenticationSubscriber implements EventSubscriberInterface
{
    /**
     * @var LoginManagerInterface
     */
    private $loginManager;
    
    /**
     * @var string
     */
    private $firewallName;

    /**
     * AuthenticationListener constructor.
     *
     * @param string $firewallName
     */
    public function __construct(LoginManagerInterface $loginManager, $firewallName)
    {
        $this->loginManager     = $loginManager;
        $this->firewallName     = $firewallName;
    }

    /**
     * {@inheritdoc}
     */
    public static function getSubscribedEvents()
    {
        return [
            UserEvent::REGISTER             => 'authenticate',
            UserEvent::REGISTER_CONFIRM     => 'authenticate',
            UserEvent::RESETTING_COMPLETE   => 'authenticate',
        ];
    }
    
    public function authenticate(UserEvent $event, EventDispatcherInterface $eventDispatcher)
    {
        try {
            $this->loginManager->loginUser($this->firewallName, $event->getUser(), $event->getResponse());

//            $eventDispatcher->dispatch(FOSUserEvents::SECURITY_IMPLICIT_LOGIN, new UserEvent($event->getUser(), $event->getRequest()));
        } catch (AccountStatusException $ex) {
            // We simply do not authenticate users which do not pass the user
            // checker (not enabled, expired, etc.).
        }
    }
}
