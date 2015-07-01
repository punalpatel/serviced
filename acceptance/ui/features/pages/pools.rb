require 'site_prism'

class Pools < SitePrism::Page
    set_url applicationURL("#/pools")
    set_url_matcher /pools/

    element :addPool_button, "[ng-click='modalAddPool()']"
    element :poolName_input, "input[name='new_pool_name']"
    element :description_input, "input[name='new_pool_description']"
end
