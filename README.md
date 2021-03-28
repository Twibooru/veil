veil
====

Like [camo](https://github.com/atmos/camo/) but not.

## Configuration / Usage

Set `VEIL_KEY` to your Camo key, and `VEIL_PROXY` to a proxy hostname:port if you want to proxy outgoing requests. Then, `bundle exec puma Config.ru`, or pick a better Rack app server and hope for the best.

Works just like Camo. Point any existing app using Camo at Veil instead, and it should Just Work.

