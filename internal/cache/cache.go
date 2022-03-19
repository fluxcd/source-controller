/*
Copyright 2022 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cache

import (
	"fmt"
	"runtime"
	"sync"
	"time"
)

// NOTE: this is heavily based on patrickmn/go-cache:
// https://github.com/patrickmn/go-cache

// Cache is a thread-safe in-memory key/value store.
type Cache struct {
	*cache
}

// Item is an item stored in the cache.
type Item struct {
	Object     interface{}
	Expiration int64
}

type cache struct {
	// Items holds the elements in the cache.
	Items map[string]Item
	// Maximum number of items the cache can hold.
	MaxItems int
	mu       sync.RWMutex
	janitor  *janitor
}

// ItemCount returns the number of items in the cache.
// This may include items that have expired, but have not yet been cleaned up.
func (c *cache) ItemCount() int {
	c.mu.RLock()
	n := len(c.Items)
	c.mu.RUnlock()
	return n
}

func (c *cache) set(key string, value interface{}, expiration time.Duration) {
	var e int64
	if expiration > 0 {
		e = time.Now().Add(expiration).UnixNano()
	}

	c.Items[key] = Item{
		Object:     value,
		Expiration: e,
	}
}

// Set adds an item to the cache, replacing any existing item.
// If expiration is zero, the item never expires.
// If the cache is full, Set will return an error.
func (c *cache) Set(key string, value interface{}, expiration time.Duration) error {
	c.mu.Lock()
	_, found := c.Items[key]
	if found {
		c.set(key, value, expiration)
		c.mu.Unlock()
		return nil
	}

	if c.MaxItems > 0 && len(c.Items) < c.MaxItems {
		c.set(key, value, expiration)
		c.mu.Unlock()
		return nil
	}

	c.mu.Unlock()
	return fmt.Errorf("Cache is full")
}

func (c *cache) Add(key string, value interface{}, expiration time.Duration) error {
	c.mu.Lock()
	_, found := c.Items[key]
	if found {
		c.mu.Unlock()
		return fmt.Errorf("Item %s already exists", key)
	}

	if c.MaxItems > 0 && len(c.Items) < c.MaxItems {
		c.set(key, value, expiration)
		c.mu.Unlock()
		return nil
	}

	c.mu.Unlock()
	return fmt.Errorf("Cache is full")
}

func (c *cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	item, found := c.Items[key]
	if !found {
		c.mu.RUnlock()
		return nil, false
	}
	if item.Expiration > 0 {
		if item.Expiration < time.Now().UnixNano() {
			c.mu.RUnlock()
			return nil, false
		}
	}
	c.mu.RUnlock()
	return item.Object, true
}

func (c *cache) Delete(key string) {
	c.mu.Lock()
	delete(c.Items, key)
	c.mu.Unlock()
}

func (c *cache) Clear() {
	c.mu.Lock()
	c.Items = make(map[string]Item)
	c.mu.Unlock()
}

func (c *cache) HasExpired(key string) bool {
	c.mu.RLock()
	item, ok := c.Items[key]
	if !ok {
		c.mu.RUnlock()
		return true
	}
	if item.Expiration > 0 {
		if item.Expiration < time.Now().UnixNano() {
			c.mu.RUnlock()
			return true
		}
	}
	c.mu.RUnlock()
	return false
}

func (c *cache) SetExpiration(key string, expiration time.Duration) {
	c.mu.Lock()
	item, ok := c.Items[key]
	if !ok {
		c.mu.Unlock()
		return
	}
	item.Expiration = time.Now().Add(expiration).UnixNano()
	c.mu.Unlock()
}

func (c *cache) GetExpiration(key string) time.Duration {
	c.mu.RLock()
	item, ok := c.Items[key]
	if !ok {
		c.mu.RUnlock()
		return 0
	}
	if item.Expiration > 0 {
		if item.Expiration < time.Now().UnixNano() {
			c.mu.RUnlock()
			return 0
		}
	}
	c.mu.RUnlock()
	return time.Duration(item.Expiration - time.Now().UnixNano())
}

func (c *cache) DeleteExpired() {
	c.mu.Lock()
	for k, v := range c.Items {
		if v.Expiration > 0 && v.Expiration < time.Now().UnixNano() {
			delete(c.Items, k)
		}
	}
	c.mu.Unlock()
}

type janitor struct {
	Interval time.Duration
	stop     chan bool
}

func (j *janitor) Run(c *cache) {
	ticker := time.NewTicker(j.Interval)
	for {
		select {
		case <-ticker.C:
			c.DeleteExpired()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

func stopJanitor(c *Cache) {
	c.janitor.stop <- true
}

func New(maxItems int, interval time.Duration) *Cache {
	c := &cache{
		Items:    make(map[string]Item),
		MaxItems: maxItems,
		janitor: &janitor{
			Interval: interval,
			stop:     make(chan bool),
		},
	}

	C := &Cache{c}

	if interval > 0 {
		go c.janitor.Run(c)
		runtime.SetFinalizer(C, stopJanitor)
	}

	return C
}
