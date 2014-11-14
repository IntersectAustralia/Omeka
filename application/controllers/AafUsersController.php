<?php

require_once "php-jwt/lib/JWT/Authentication/JWT.php";
use JWT\Authentication\JWT;
require_once "UsersController.php";

/**
 * @package Omeka\Controller
 */
class AafUsersController extends UsersController
{
	public function loginAction() {
		$this->_helper->viewRenderer->renderScript('aaf.php');
	}

	public function authAction() {
    if ($this->getRequest()->isPost()) {
      $secret = "w#*5@lT'.1%}11>}0\DU0|r+%b_S4$^5";
      $jws = $this->_request->getPost('assertion');
      $jwt = JWT::decode($jws, $secret);

      # In a complete app we'd also store and validate the jti value to ensure there is no reply on this unique token ID
      $now = strtotime("now");
      echo $jwt->iss;
      echo $jwt->aud;
      echo strtotime($jwt->exp);
      echo $now;
      echo strtotime($jwt->nbf);
      if($jwt->iss == 'https://rapid.test.aaf.edu.au' &&
        $jwt->aud == 'https://aaf-rc-test-php.intersect.org.au' && strtotime($jwt->exp) < $now && $now > strtotime($jwt->nbf)) {
      	$aafNamespace = new Zend_Session_Namespace('aaf');
        $aafNamespace->jws = $jws;
        $aafNamespace->jwt = $jwt;
        $this->_helper->redirector->gotoUrl('/');
      } else {
      	echo "Aborted!!!";
      	echo $now;
      	throw new Omeka_Controller_Exception_403(__("JWS is invalid."));
      }
    }
	}
}