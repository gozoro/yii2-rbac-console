<?php



namespace gozoro\rbac\console;

use Yii;
use yii\console\ExitCode;
use yii\helpers\Console;

use yii\rbac\Permission;
use yii\rbac\Role;
use yii\rbac\Rule;




/**
 *
 * RBAC configuration and managment tool in the console.
 *
  * Example RBAC config:
 *	```
 * [
 *    // Permission list
 *    'permissions' =>[
 *        'read' => 'permissions for read something',   // name => description
 *        'write' => 'permissions for write something', // name => description
 *    ],
 *
 *    // Role list
 *    'roles' => [
 *        'role_admin' => 'Administrator role', // name => description
 *        'role_manager' => 'Manager role',     // name => description
 *    ],
 *
 *	   // Rule list
 *	  'rules' => [
 *			\WriteRule:class => ['write'], // rule for permission "write"
 *	   ],
 *
 *    // Mapping roles to permissions
 *    'access' => [
 *        'role_admin' => ['read', 'write'], // array of permissions
 *        'role_manager' => ['read'],
 *    ],
 * ]
 * ```
 */
abstract class RbacController extends \yii\console\Controller
{
	public $defaultAction = 'show';




	/**
	 * The method must returns an instance of a class with the interface \yii\web\Identity by user ID.
	 */
	abstract function findIdentityById($userId);

	/**
	 * The method must returns an instance of a class with the interface \yii\web\Identity by username.
	 */
	abstract function findIdentityByUsername($username);


	/**
	 * Returns user fileds to display
	 * @return array
	 */
	public function showUserFields($userFields)
	{
		return $userFields;
	}

	/**
	 * Returns rbac manager
	 * @return \yii\rbac\ManagerInterface
	 */
	public function getAuthManager()
	{
		return Yii::$app->authManager;
	}

	/**
	 * Print error and exit
	 */
	protected function error($errMessage)
	{
		$this->stdout("$errMessage\n\n", Console::FG_RED);
		return ExitCode::UNSPECIFIED_ERROR;
	}

	/**
	 * Returns path to RBAC-config
	 * @return string
	 */
	public function getConfigPath()
	{
		return '@app/config/rbac.php';
	}

	/**
	 * Returns config array
	 * @return array
	 */
	public function getConfig()
	{
		$path = $this->getConfigPath();
		$configfile = Yii::getAlias($path);

		if(file_exists($configfile))
		{
			return require($configfile);
		}
		else
		{
			return $this->error("RBAC config $configfile is not exist.");
		}
	}


	/**
	 * Displays config
	 */
	public function actionShowConfig()
	{
		print "RBAC config:\n";
		print \Yii::getAlias($this->getConfigPath())."\n\n";

		$config = $this->getConfig();

		print_r($config);

		print "\n\n";
		return ExitCode::OK;
	}




	protected function initVerify()
	{
 		$config = $this->getConfig();

		if( isset($config['permissions']) )
		{
			if(is_array($config['permissions']))
			{
				foreach($config['permissions'] as $key => $val)
				{
					if(\is_string($key) and \is_string($val))
					{
						// ok
					}
					elseif($val instanceof Permission)
					{
						// ok
					}
					elseif(\is_string($key) and \is_array($val))
					{
						// ok
					}
					elseif(!\is_string($key) and \is_array($val) )
					{
						if(empty($val['name']))
						{
							return $this->error("The permissions[$key] value array must have the [name] key.");

						}
					}
					else
					{
						return $this->error("The permissions[$key] value must be string or array or instance of Permission.");
					}
				}
			}
			else
			{
				return $this->error("The [permissions] must be array.");
			}
		}
		else
		{
			return $this->error("The [permissions] is missing in the RBAC config.");
		}


		if( isset($config['roles']) )
		{
			if(\is_array($config['roles']))
			{
				foreach($config['roles'] as $key => $val)
				{
					if(\is_string($key) and \is_string($val))
					{
						// ok
					}
					elseif($val instanceof Role)
					{
						// ok
					}
					elseif(\is_string($key) and \is_array($val))
					{
						// ok
					}
					elseif(!\is_string($key) and \is_array($val) )
					{
						if(empty($val['name']))
							return $this->error("The roles[$key] value array must have the [name] key.");
					}
					else
					{
						return $this->error("The roles[$key] value must be string or array or instance of Role.");
					}
				}
			}
			else
			{
				return $this->error("The [roles] must be array.");
			}

		}
		else
			return $this->error("The [roles] is missing in the RBAC config.");



		if(isset($config['rules']))
		{
			if(\is_array($config['rules']))
			{
				foreach($config['rules'] as $key => $val)
				{
					if(is_string($key))
					{
						if(!\class_exists($key))
						{
							return $this->error("Class [$key] not found.");
						}
					}
					else
						return $this->error("The rule keys must be string (rule class name).");


					$val = (array)$val;
					foreach($val as $item)
					{
						if(!\is_string($item))
							return $this->error("The rules[$key] value must be string or array of strings.");
					}
				}
			}
			else
			{
				return $this->error("The [rules] must be array (key is rule class name).");
			}
		}


		if( isset($config['access']) )
		{
			if(\is_array($config['access']))
			{
				foreach($config['access'] as $key => $val)
				{
					if(!is_string($key))
						return $this->error("The access key must be string (permission name or role name).");

					$val = (array)$val;
					foreach($val as $item)
					{
						if(!\is_string($item))
							return $this->error("The access[$key] value must be string or array of strings (permission name or role name).");
					}
				}
			}
			else
			{
				return $this->error("The [access] must be array.");
			}
		}
		else
			return $this->error("The [access] is missing in the RBAC config.");
	}

	/**
	 * Performs initial RBAC configuration (remembers user roles, deletes all data, revert data from the config, restores users roles).
	 * You can use it after adding new roles or removing not need roles.
	 */
	public function actionInit()
	{
		$configfile = Yii::getAlias( $this->getConfigPath() );
		if(!$this->confirm("Initialize RBAC scheme from $configfile."))
		{
			return ExitCode::OK;
		}


 		$config      = $this->getConfig();
 		$authManager = $this->getAuthManager();
 		$userRoles   = [];

		$this->initVerify();


		print "Get user roles: ";
		foreach($authManager->getRoles() as $role)
		{
			$userRoles[ $role->name ] = $authManager->getUserIdsByRole($role->name);
		}
		$this->stdout("OK\n", Console::FG_GREEN);

		print "Clear RBAC data: ";
		$authManager->removeAll();
		$this->stdout("OK\n", Console::FG_GREEN);

		$rules       = [];
		$permissions = [];
		$roles       = [];



		if(isset($config['rules']))
		{
			print "Configure rules:\n";
			foreach($config['rules'] as $ruleClass => $items)
			{
				if(\is_string($ruleClass))
				{
					$rule = new $ruleClass();
				}
				elseif($ruleClass instanceof Rule)
				{
					$rule = $ruleClass;
				}
				else
				{
					return $this->error("The rule key must be string of class name.");
				}


				$authManager->add($rule);
				$this->stdout(" + add rule [".$rule->name."]\n", Console::FG_GREEN);

				$items = (array)$items;
				foreach($items as $item)
				{
					if(\is_string($item))
					{
						$rules[ $item ] = $rule;
					}
					else
					{
						$this->stdout(" - error: item of rule [".$rule->name."] must be string.\n", Console::FG_RED);
					}
				}
			}
		}



		print "Configure permissions:\n";
		foreach($config['permissions'] as $permissionName => $permission)
		{
			if( \is_string($permissionName) and \is_string($permission))
			{
				$p = $authManager->createPermission($permissionName);
				$p->description = $permission;
				$permission = $p;
			}
			elseif($permission instanceof Permission)
			{
				// ok
			}
			elseif(\is_array($permission))
			{
				$p = new Permission();

				if(!empty($permission['description']))
					$p->description = $permission['description'];

				if(!empty($permission['name']))
					$p->name = $permission['name'];
				else
					$p->name = $permissionName;

				if(!empty($permission['data']))
					$p->data = $permission['data'];


				if( !isset($permission['description']) and !isset($permission['name']) and !isset($permission['data']) )
					$p->data = $permission;

				$permission = $p;
			}
			else
			{
				return $this->error("The permission value must be string or instance of Permission (permissions[$permissionName]).");
			}

			$withRule = "";
			if(isset($rules[$permissionName]))
			{
				$permission->ruleName = $rules[$permissionName]->name;
				$withRule = " with rule [".$permission->ruleName."]";
			}

			$authManager->add( $permission );
			$permissions[$permissionName] = $permission;
			$this->stdout(" + add permission [".$permission->name."]$withRule - ".$permission->description."\n", Console::FG_GREEN);
		}


		print "Configure roles:\n";
		foreach($config['roles'] as $roleName => $role)
		{
			if(\is_string($role))
			{
				$r = $authManager->createRole($roleName);
				$r->description = $role;
				$role = $r;
			}
			elseif($role instanceof Role)
			{
				$role->name = $roleName;
			}
			elseif(\is_array($role))
			{
				$r = new Role();

				if(!empty($role['description']))
					$r->description = $role['description'];

				if(!empty($role['name']))
					$r->name = $role['name'];
				else
					$r->name = $roleName;

				if(!empty($role['data']))
					$r->data = $role['data'];


				if( !isset($role['description']) and !isset($role['name']) and !isset($role['data']) )
					$r->data = $role;

				$role = $r;
			}
			else
			{
				return $this->error("The role value must be string or instance of Role (roles[$roleName]).");
			}

			$withRule = "";
			if(isset($rules[$roleName]))
			{
				$role->ruleName = $rules[$roleName]->name;
				$withRule = " with rule [".$role->ruleName."]";
			}

			$role->name = $roleName;


			$authManager->add( $role );
			$roles[ $roleName ] = $role;
			$this->stdout(" + add role [".$role->name."]$withRule - ".$role->description."\n", Console::FG_GREEN);
		}



		print "Configure access:\n";
		foreach($config['access'] as $itemName => $access)
		{
			if(isset($permissions[$itemName]))
			{
				$item = $permissions[$itemName];

				$access = (array)$access;

				foreach($access as $accessItemName)
				{
					if(\is_string($accessItemName))
					{
						if(isset($permissions[$accessItemName]))
						{
							$authManager->addChild($item, $permissions[$accessItemName]);
							$this->stdout(" + permission [".$item->name."] has child permission [".$permissions[$accessItemName]->name."]\n", Console::FG_GREEN);
						}
						elseif(isset($roles[$accessItemName]))
						{
							$authManager->addChild($item, $roles[$accessItemName]);
							$this->stdout(" + permission [".$item->name."] has child role [".$roles[$accessItemName]->name."]\n", Console::FG_GREEN);
						}
						else
						{
							$this->stdout(" - error: item [$accessItemName] not found in RBAC config.\n", Console::FG_RED);
						}
					}
					else
					{
						$this->stdout(" - error: access item is not a string.", Console::FG_RED);
					}
				}
			}
			elseif(isset($roles[$itemName]))
			{
				$item = $roles[$itemName];

				$access = (array)$access;

				foreach($access as $accessItemName)
				{
					if(\is_string($accessItemName))
					{
						if(isset($permissions[$accessItemName]))
						{
							$authManager->addChild($item, $permissions[$accessItemName]);
							$this->stdout(" + role [".$item->name."] has child permission [".$permissions[$accessItemName]->name."]\n",  Console::FG_GREEN);
						}
						elseif(isset($roles[$accessItemName]))
						{
							$authManager->addChild($item, $roles[$accessItemName]);
							$this->stdout(" + role [".$item->name."] has child role [".$roles[$accessItemName]->name."]\n", Console::FG_GREEN);
						}
						else
						{
							$this->stdout(" - error: item [$accessItemName] not found in RBAC config.\n", Console::FG_RED);
						}
					}
					else
					{
						$this->stdout(" - error: access item is not a string.", Console::FG_RED);
					}
				}

			}
			else
			{
				$this->stdout(" - error: item name [$itemName] not found.\n",  Console::FG_RED);
			}
		}


		print "Configure users: ";
		foreach($userRoles as $roleName => $userIds)
		{
			$role = $authManager->getRole($roleName);

			if(!is_null($role))
			foreach($userIds as $userId)
			{
				$authManager->assign($role, $userId);
			}
		}
		$this->stdout("OK\n", Console::FG_GREEN);

		print "\n";
		return ExitCode::OK;
	}


	/**
	 * Displays a list of roles and users
	 */
	public function actionShow()
	{
		$authManager = $this->getAuthManager();
		$roles       = $authManager->getRoles();

		if($roles) foreach($roles as $role)
		{
			print $role->name." (".$role->description."):\n";

			$rows = [];

			$roleUsers = $authManager->getUserIdsByRole($role->name);

			if($roleUsers)
			{
				foreach($roleUsers as $userId)
				{
					$user = $this->findIdentityById($userId);

					if($user)
					{
						if(method_exists($user, 'toArray'))
						{
							$userArr = $this->showUserFields( $user->toArray() );
							$keys = \array_keys($userArr);
							$rows[] = $userArr;
						}
						else
						{
							$keys = ['id', ''];
							$rows[] = [
								'id' => $user->getId(),
								"add a method ".get_class($user)."::toArray() for more information"
							];
						}
					}
				}

				$table = new \yii\console\widgets\Table();
				$table->setHeaders($keys);
				$table->setRows($rows);
				print $table->run();
			}
			else
			{
				$this->stdout("...no users\n",  Console::FG_YELLOW);
			}



			print "\n";
		}
		else
		{
			$this->stdout("...roles empty\n",  Console::FG_YELLOW);
		}

		print "\n";

		return ExitCode::OK;
	}


	/**
	 * Assigns a role (or a permission) to a user.
	 * @param string $rolename role name or permission name
	 * @param string $username user name
	 */
	public function actionAssign($rolename, $username)
	{
		print "\n";
		$authManager = $this->getAuthManager();
		$perm        = $authManager->getPermission($rolename);
		$role        = $authManager->getRole($rolename);

		if($perm)
		{
			$type = 'permission';
			$item = $perm;
		}

		if($role)
		{
			$type = 'role';
			$item = $role;
		}

		if(empty($item))
		{
			return $this->error("Role [$rolename] is not found.\nPermission [$rolename] is not found.");
		}


		$identity = $this->findIdentityByUsername($username);

		if(is_null($identity))
		{
			return $this->error("User [$username] is not found.");
		}

		$userId = $identity->getId();


		if($type == 'role')
		{
			$userRoles = $authManager->getRolesByUser($userId);
			if(isset($userRoles[$rolename]))
			{
				return $this->error("User [$username] already has a role [$rolename].");
			}
		}
		else
		{
			$userPermissions = $authManager->getPermissionsByUser($userId);
			if(isset($userPermissions[$rolename]))
			{
				return $this->error("User [$username] already has a permission [$rolename].");
			}
		}



		if($authManager->assign($item, $userId))
		{
			$this->stdout("The user [$username] was successfully assigned to the $type [$rolename].\n", Console::FG_GREEN);
			return ExitCode::OK;
		}
		else
		{
			return $this->error("The $type failed assigned.");
		}

		return ExitCode::OK;
	}


	/**
	 * Revokes role or permission from a user.
	 * @param string $rolename role name or permission name
	 * @param string $username
	 */
	public function actionUnassign($rolename, $username)
	{
		print "\n";

		$authManager = $this->getAuthManager();
		$perm        = $authManager->getPermission($rolename);
		$role        = $authManager->getRole($rolename);
		$item        = null;
		$type        = null;

		if($perm)
		{
			$type = 'permission';
			$item = $perm;
		}

		if($role)
		{
			$type = 'role';
			$item = $role;
		}

		if(empty($item))
		{
			return $this->error("Role [$rolename] is not found.\nPermission [$rolename] is not found.");
		}


		$identity = $this->findIdentityByUsername($username);

		if(is_null($identity))
		{
			return $this->error("User [$username] is not found.");
		}

		$userId = $identity->getId();


		if($authManager->revoke($item, $userId))
		{
			$this->stdout("The $type [$rolename] successfully revoked from user [$username].\n\n", Console::FG_GREEN);
			return ExitCode::OK;
		}
		else
		{
			return $this->error("The $type failed revoked.");
		}
	}


	/**
	 * Revokes all roles and permissions from a user.
	 * @param string $username
	 */
	public function actionUnassignAll($username)
	{
		$authManager = $this->getAuthManager();
		$identity    = $this->findIdentityByUsername($username);

		if(is_null($identity))
		{
			return $this->error("User [$username] is not found.\n\n");
		}

		$userId = $identity->getId();

		if($authManager->revokeAll($userId))
		{
			$this->stdout("Revoked all roles from user [$username].\n\n",  Console::FG_GREEN);
		}
		else
		{
			$this->stdout("Failed revoke from [$username].\n\n", Console::FG_RED);
		}

		print "\n";
		return ExitCode::OK;
	}


	/**
	 * Displays a list of roles from AuthManager.
	 */
	public function actionRoles()
	{
		$authManager = $this->getAuthManager();
		$items = $authManager->getRoles();

		print "Roles:\n";

		if(empty($items))
		{
			$this->stdout("...empty\n", Console::FG_YELLOW);
		}
		else
		{
			$rows = [];
			foreach($items as $item)
			{
				$rows[] = [
					$item->name,
					$item->description
				];
			}


			$table = new \yii\console\widgets\Table();
			$table->setHeaders(['name', 'description']);
			$table->setRows($rows);
			print $table->run();
		}

		print "\n";
		return ExitCode::OK;
	}


	/**
	 * Displays a list of permissions from AuthManager.
	 */
	public function actionPermissions()
	{
		$authManager = $this->getAuthManager();
		$items = $authManager->getPermissions();

		print "Permissions:\n";

		if(empty($items))
		{
			$this->stdout("...empty\n", Console::FG_YELLOW);
		}
		else
		{
			$rows = [];
			foreach($items as $item)
			{
				$rows[] = [
					$item->name,
					$item->description
				];
			}


			$table = new \yii\console\widgets\Table();
			$table->setHeaders(['name', 'description']);
			$table->setRows($rows);
			print $table->run();
		}

		print "\n";

		return ExitCode::OK;
	}


	/**
	 * Displays roles and permissions of user
	 * @param string $username
	 */
	public function actionShowUser($username)
	{
		$authManager = $this->getAuthManager();
		$identity    = $this->findIdentityByUsername($username);

		if(is_null($identity))
		{
			return $this->error("User [$username] is not found.");
		}

		$userId = $identity->getId();

		$roles = $authManager->getRolesByUser($userId);
		$permissions = $authManager->getPermissionsByUser($userId);

		print "Roles of [$username]:\n";
		if($roles)
		{
			$rows = [];
			foreach($roles as $role)
			{
				$rows[] = [$role->name, $role->description];
			}

			$table = new \yii\console\widgets\Table();
			$table->setHeaders(['name', 'description']);
			$table->setRows($rows);
			print $table->run();
		}
		else
		{
			$this->stdout("...empty\n", Console::FG_YELLOW);
		}

		print "\n";

		print "Permissions of [$username]:\n";
		if($permissions)
		{
			$rows = [];
			foreach($permissions as $perm)
			{
				$rows[] = [$perm->name, $perm->description];
			}

			$table = new \yii\console\widgets\Table();
			$table->setHeaders(['name', 'description']);
			$table->setRows($rows);
			print $table->run();
		}
		else
		{
			$this->stdout("...empty\n", Console::FG_YELLOW);
		}
		return ExitCode::OK;
	}
}