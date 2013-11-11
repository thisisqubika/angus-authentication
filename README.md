# angus-authentication

Adds an authentication layer for [Rack][rack] applications.

While it can be used as a micro-framework, it's primarily and focused purpose is
http request routing.

angus-router doesn't handle unregisterd routes, it doesn't provide a template rendering mechanism,
and so on. Those features should be fulfilled at framework level.

[rack]: http://rubygems.org/gems/rack

## Usage

Routes are registered with #on method.

  ``` ruby
  router.on(:get, '/hello') do
    [200, {}, ['Hello']]
  end
  ```

  #route receives a Rack environment, lookups for a route matching the request's path
  and invokes the corresponding block.


  ``` ruby
  router.route(env)
  ```

If no matching registered route, a ```NotImplementedError``` is raised.


Supported HTTP methods:

 - get
 - post
 - put
 - delete
 - head
 - options
 - patch
 - trace


## Usage sample

  ``` ruby
  # config.ru
  require 'angus-router'

  router = Angus::Router.new

  router.on(:get, '/') do
    [200, {}, ['Index Page']]
  end

  router.on(:get, '/hello') do
    [200, {}, ['Hello']]
  end

  router.on(:get, '/hello/:dude') do |env, params|
    [200, {}, ["Hello #{params[:dude]}!"]]
  end

  run ->(env) { router.route(env) }
  ```

## Installation

Install angus-router as a gem.

  ``` shell
  gem install angus-router
  ```
