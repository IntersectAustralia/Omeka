<?php

require_once "php-jwt/lib/JWT/Authentication/JWT.php";
use JWT\Authentication\JWT;

require_once "UsersController.php";

/**
 * @package Omeka\Controller
 */
class AafUsersController extends UsersController
{
    public function loginAction()
    {
        $this->_helper->viewRenderer->renderScript('aaf.php');
    }

    public function authAction()
    {
        if (!$this->getRequest()->isPost()) {
            return;
        }

        $aaf_config_file = CONFIG_DIR . '/aaf.ini';
        $aaf_config = new Zend_Config_Ini($aaf_config_file, 'production');

        $secret = $aaf_config->secret;
        $jws = $this->_request->getPost('assertion');
        $jwt = JWT::decode($jws, $secret);

        # In a complete app we'd also store and validate the jti value to ensure there is no reply on this unique token ID
        $now = strtotime("now");
        if ($jwt->iss == $aaf_config->jwt->iss &&
            $jwt->aud == $aaf_config->jwt->aud && strtotime($jwt->exp) < $now && $now > strtotime($jwt->nbf)
        ) {
            $email = $jwt->{'https://aaf.edu.au/attributes'}->{'mail'};
            $password = 'AAFauthenticated';
            $userTable = get_db()->getTable('User');
            $user = $userTable->findBySql("email = ?", array($email), true);
            if (!$user) {
                $aaf_user = new User();
                $aaf_user->username = $email;
                $aaf_user->setPassword($password);
                $aaf_user->active = 1;
                $aaf_user->role = "researcher";
                $aaf_user->name = $jwt->{'https://aaf.edu.au/attributes'}->{'displayname'};
                $aaf_user->email = $email;
                $aaf_user->save();
            }

            $authAdapter = new Omeka_Auth_Adapter_UserTable($this->_helper->db->getDb());
            $authAdapter->setIdentity($email)->setCredential($password);
            $authResult = $this->_auth->authenticate($authAdapter);

            if (!$authResult->isValid()) {
                $this->_helper->flashMessenger($this->getLoginErrorMessages($authResult), 'error');
            }

            $this->_helper->FlashMessenger('Successful Login');
            $aaf_session = new Zend_Session_Namespace('aaf');
            $aaf_session->jws = $jws;
            $aaf_session->jwt = $jwt;
            if ($aaf_session->redirect) {
                $this->_helper->redirector->gotoUrl($aaf_session->redirect);
            } else {
                $this->_helper->redirector->gotoUrl('/');
            }
        } else {
            echo "Aborted!!!";
            echo $now;
            throw new Omeka_Controller_Exception_403(__("JWS is invalid."));
        }
    }
}