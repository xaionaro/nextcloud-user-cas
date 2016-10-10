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

/**
 * This class contains all hooks.
 */
class OC_USER_CAS_Hooks {

	static public function post_login($parameters) {

		$uid = $parameters['uid'];
		$casBackend = OC_USER_CAS::getInstance();
		$userDatabase = new OC\User\Database;

		if (phpCAS::isAuthenticated()) {
			// $cas_attributes may vary in name, therefore attributes are fetched to $attributes
			$cas_attributes = phpCAS::getAttributes();
			$cas_uid = phpCAS::getUser();

			// parameters 
			$attributes = array();


			if ($cas_uid == $uid) {
				\OCP\Util::writeLog('cas','attr  \"'.implode(',',$cas_attributes).'\" for the user: '.$uid, \OCP\Util::DEBUG);


				if (array_key_exists($casBackend->displayNameMapping, $cas_attributes)) 
					$attributes['cas_name'] = $cas_attributes[$casBackend->displayNameMapping];	
				else 
					$attributes['cas_name'] = $cas_attributes['cn'];
                
				if (array_key_exists($casBackend->mailMapping, $cas_attributes)) 
					$attributes['cas_email'] = $cas_attributes[$casBackend->mailMapping];
				else 
					$attributes['cas_email'] = $cas_attributes['mail'];

				if (array_key_exists($casBackend->groupMapping, $cas_attributes)) {
					$attributes['cas_groups'] = $cas_attributes[$casBackend->groupMapping];
				}
				else if (!empty($casBackend->defaultGroup)) {
					$attributes['cas_groups'] = array($casBackend->defaultGroup);
					\OCP\Util::writeLog('cas','Using default group "'.$casBackend->defaultGroup.'" for the user: '.$uid, \OCP\Util::DEBUG);
				}

				if (!$userDatabase->userExists($uid) && $casBackend->autocreate) {
					// create users if they do not exist
					if (preg_match( '/[^a-zA-Z0-9 _\.@\-]/', $uid)) {
						\OCP\Util::writeLog('cas','Invalid username "'.$uid.'", allowed chars "a-zA-Z0-9" and "_.@-" ',\OCP\Util::DEBUG);
						return false;
					}
					else {
						$random_password = \OCP\Util::generateRandomBytes(20);
						\OCP\Util::writeLog('cas','Creating new user: '.$uid, \OCP\Util::DEBUG);
						$userDatabase->createUser($uid, $random_password);

						// after creating the user, fill the attributes
						if($userDatabase->userExists($uid)) 
							OC_USER_CAS::getInstance()->update_user($uid, $attributes);

						return true;
					}
				}

				// try to update user attributes
				if ($casBackend->updateUserData) 
					OC_USER_CAS::getInstance()->update_user($cas_uid, $attributes);

				return true;
			}
		}
		return false;
	}

/*
*/

	static public function logout($parameters) {
		if (\OC::$server->getConfig()->getAppValue('user_cas', 'cas_disable_logout', false)) {
			return true;
		}

		$casBackend = OC_USER_CAS::getInstance();

		if (phpCAS::isAuthenticated()) 
			phpCAS::logout();
		
		return true;
	}

}
