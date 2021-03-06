<?php

/**
 * ownCloud - user_cas
 *
 * @author Sixto Martin <sixto.martin.garcia@gmail.com>
 * @copyright Sixto Martin Garcia. 2012
 * @copyright Leonis. 2014 <devteam@leonis.at>
 * @copyright Takayuki NAGAI 2016
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU AFFERO GENERAL PUBLIC LICENSE
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU AFFERO GENERAL PUBLIC LICENSE for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this library.  If not, see <http://www.gnu.org/licenses/>.
 *
 */




if (OCP\App::isEnabled('user_cas')) {

	require_once 'user_cas/user_cas.php';

	OCP\App::registerAdmin('user_cas', 'settings');

	// register user backend
	OC_User::useBackend( 'CAS' );

	OC::$CLASSPATH['OC_USER_CAS_Hooks'] = 'user_cas/lib/hooks.php';
	OCP\Util::connectHook('OC_User', 'post_createUser', 'OC_USER_CAS_Hooks', 'post_createUser');
	OCP\Util::connectHook('OC_User', 'post_login', 'OC_USER_CAS_Hooks', 'post_login');
	OCP\Util::connectHook('OC_User', 'logout', 'OC_USER_CAS_Hooks', 'logout');

	$force_login = shouldEnforceAuthentication();

	if( (isset($_GET['app']) && $_GET['app'] == 'user_cas') || $force_login ) {

		if (OC_USER_CAS :: initialized_php_cas()) {
			error_log("forceAuthentication: <".@$_GET['app']."> ".($force_login?'true':'false'));
			phpCAS::forceAuthentication();
			error_log("/forceAuthentication");

			$user = phpCAS::getUser();
			$application = new \OC\Core\Application();
			$loginController = $application->getContainer()->query('OC\Core\Controller\LoginController');
			$response = $loginController->tryLogin($user,NULL,NULL, false);
			error_log('CAS success: '.$user);
			return $response;

			if (isset($_SERVER["QUERY_STRING"]) && !empty($_SERVER["QUERY_STRING"]) && $_SERVER["QUERY_STRING"] != 'app=user_cas') {
				$uri = OC::$WEBROOT . '/?' . $_SERVER["QUERY_STRING"];
				//error_log('Redirecting to:'. $uri);
				header( 'Location: ' . $uri);
				exit();
			}
		}

		OC::$REQUESTEDAPP = '';
		//error_log('OC_Util::redirectToDefaultPage()');
		OC_Util::redirectToDefaultPage();
	}

	if (!phpCAS::isAuthenticated() && !OCP\User::isLoggedIn()) {
		OC_App::registerLogIn(array('href' => '?app=user_cas', 'name' => 'CAS Login'));
	}

}

/**
 * Check if login should be enforced using user_cas
 */
function shouldEnforceAuthentication()
{
	if (OC::$CLI) {
		return false;
	}

	/*if (OCP\Config::getAppValue('user_cas', 'cas_force_login', false) !== 'on') {
		return false;
	}*/

	if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
		return false;
	}

	if (OCP\User::isLoggedIn() || isset($_GET['admin_login']) || isset($_GET['access_token'])) {
		return false;
	}

	$script = basename($_SERVER['SCRIPT_FILENAME']);
	if (in_array(
		$script,
		array(
			'cron.php',
			'public.php',
			'remote.php',
			'status.php',
		)
	)) {
		return false;
	}

	if (strpos($_SERVER['DOCUMENT_URI'], '/index.php/s/') === 0) {
		return false;
	}

	//error_log(serialize($_SERVER));

	return true;
}

