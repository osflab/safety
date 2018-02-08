<?php

/*
 * This file is part of the OpenStates Framework (osf) package.
 * (c) Guillaume Ponçon <guillaume.poncon@openstates.com>
 * For the full copyright and license information, please read the LICENSE file distributed with the project.
 */

namespace Osf\Safety;

use Osf\Container\OsfContainer as C;
use Osf\Crypt\Crypt;
//use Osf\Log\LogProxy as Log;
use Redis;

/**
 * HTTP high level firewall
 *
 * @author Guillaume Ponçon <guillaume.poncon@openstates.com>
 * @copyright OpenStates
 * @version 1.0
 * @since OSF-2.0 - 2017
 * @package osf
 * @subpackage safety
 */
class Firewall
{
    protected const REDIS_PREFIX = 'FW:';
    protected const REDIS_BLACKLIST_SUFFIX = ':BL';
    protected const SUSPECT_URIES = [
        '/wp-login.php' => true,
        '/xmlrpc.php'   => true,
        '/?author=1'    => true,
    ];
    protected const REQUEST_RECORD_EXPIRE = 1;
    protected const TARPIT_COUNT_TRIGGER = 5;
    protected const TARPIT_WAIT_DURATION = 10;
    protected const BLACKLIST_DURATION   = 20;
    
    /**
     * @var Redis
     */
    protected $redis;
    
    protected function getKeyPrefix(string $suffix = '')
    {
        static $keyPrefix = null;
        
        if ($keyPrefix === null) {
            $keyPrefix = self::REDIS_PREFIX . filter_input(INPUT_SERVER, 'REMOTE_ADDR') . ':' 
                       . Crypt::hash(filter_input(INPUT_SERVER, 'HTTP_USER_AGENT'));
        }
        return $keyPrefix . $suffix;
    }
    
    public function check()
    {
        if ($this->getRedis()->exists($this->getKeyPrefix(self::REDIS_BLACKLIST_SUFFIX))) {
            exit;
        }
        $key = $this->getKeyPrefix(':' . microtime(true));
        $uri = filter_input(INPUT_SERVER, 'REQUEST_URI');
        $this->getRedis()->set($key, $uri);
        $this->getRedis()->expire($key, self::REQUEST_RECORD_EXPIRE);
        if (array_key_exists($uri, self::SUSPECT_URIES)) {
            $this->tarpit($uri, true, self::BLACKLIST_DURATION);
        }
        $keys = $this->getRedis()->keys($this->getKeyPrefix(':*'));
        if (count($keys) >= self::TARPIT_COUNT_TRIGGER) {
            $this->tarpit($this->getRedis()->mget($keys), true);
        }
    }
    
    /**
     * Tarpit the current client
     * @param type $msgDump
     * @param bool $die
     * @param int|null $duration
     */
    public function tarpit($msgDump = null, bool $die = false, ?int $duration = null)
    {
        $duration = $duration ?? self::TARPIT_WAIT_DURATION;
        $keyBlack = $this->getKeyPrefix(self::REDIS_BLACKLIST_SUFFIX);
        $this->getRedis()->set($keyBlack, true);
        $this->getRedis()->expire($keyBlack, $duration);
        $die && exit;
    }
    
    /**
     * @param Redis $redis
     * @return $this
     */
    public function setRedis(Redis $redis)
    {
        $this->redis = $redis;
        return $this;
    }
    
    /**
     * @return Redis
     */
    protected function getRedis(): Redis
    {
        if (!($this->redis instanceof Redis)) {
            $this->setRedis(C::getCache()->getRedis());
        }
        return $this->redis;
    }
}
