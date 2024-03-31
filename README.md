# yii2-rbac-console

RBAC configuration and managment tool in the console.



## Installation

```code
composer require gozoro/yii2-rbac-console
```

## Preparation

Create console controller `commands\RbacController.php`.


```php

namespace app\commands;


class RbacController extends \gozoro\yii2\rbac\console\RbacController;
{
	public function findIdentityByUsername($username)
	{
		//TODO:: Return an instance of the class with interface \yii\web\Identity

		// example:
		//return UserIdentity::find()->where(['username'=>$username])->one();
	}

	public function findIdentityById($userId)
	{
		//TODO:: Return an instance of the class with interface \yii\web\Identity

		// example:
		//return UserIdentity::find()->where(['id'=>$userId])->one();
	}
}

```


## Controller actions

- `./yii rbac/init` Performs initial RBAC configuration (remembers user roles, deletes all data, revert data from the config, restores users roles).
You can use it after adding new roles or removing not need roles.

- `rbac/show-config` Displays config (default config: `@app/config/rbac.php`).

- `rbac/roles` Displays a list of roles from AuthManager.

- `rbac/permissions` Displays a list of permissions from AuthManager.

- `rbac/show` (default) Displays a list of roles and users.

- `rbac/assign` Assigns a role (or a permission) to a user.
    
- `rbac/show-user` Displays roles and permissions of user.

- `rbac/unassign` Revokes role or permission from a user.

- `rbac/unassign-all` Revokes all roles and permissions from a user.


## Configuration

Create config `@app/config/rbac.php`.

Example:
```php
 return [
 	// Permission list
 	'permissions' =>[
 		'read' => 'permissions for read something',   // permission_name => description
    	'write' => 'permissions for write something', // permission_name => description

		'special' => $permision, // permission_name => permission object
		'special2' => [ // permission_name => permission as array
			'name' => ...,
			'description' => ...,
			'data' => ...,
		], 
 	],
 
	// Role list
 	'roles' => [
 		'role_admin' => 'Administrator role', // role_name => description
 		'role_manager' => 'Manager role',     // role_name => description
		'role_viewer' => $role, // role_name => role_object
		'role_something' => [ // role_name => role as array
			'name' => ...,
			'description' => ...,
			'data' => ...,
		],

 	],
 
	// Rule list
	'rules' => [
		\WriteRule:class => ['write'], // rule for permission "write"
		$rule => ['write', 'read'], // rule object for permissions "write" and "read"
	],
 
     // Mapping roles to permissions
	'access' => [
		'role_admin' => ['read', 'write'], // array of permissions
		'role_manager' => ['read'],
	],
]; 
```

Use command `./yii rbac/init` to initialize or re-initialize.


