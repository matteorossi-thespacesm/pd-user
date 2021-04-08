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

use Symfony\Component\HttpFoundation\Response;

use Pd\UserBundle\Model\UserInterface;

interface LoginManagerInterface
{
    /**
     * @param string $firewallName
     */
    public function loginUser($firewallName, UserInterface $user, Response $response = null);
}
