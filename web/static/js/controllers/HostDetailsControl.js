function HostDetailsControl($scope, $routeParams, $location, resourcesService, authService, $modalService, $translate) {
    // Ensure logged in
    authService.checkLogin($scope);

    $scope.name = "hostdetails";
    $scope.params = $routeParams;

    $scope.breadcrumbs = [
        { label: 'breadcrumb_hosts', url: '#/hosts' }
    ];

    $scope.resourcesService = resourcesService;

    // Also ensure we have a list of hosts
    refreshHosts($scope, resourcesService, true);

    $scope.running = buildTable('Name', [
        { id: 'Name', name: 'label_service' },
        { id: 'StartedAt', name: 'running_tbl_start' },
        { id: 'View', name: 'running_tbl_actions' }
    ]);

    $scope.ip_addresses = buildTable('Interface', [
        { id: 'Interface', name: 'ip_addresses_interface' },
        { id: 'Ip', name: 'ip_addresses_ip' },
        { id: 'MAC Address', name: 'ip_addresses_mac' }
    ]);

    $scope.viewLog = function(running) {
        $scope.editService = $.extend({}, running);
        resourcesService.get_service_state_logs(running.ServiceID, running.ID, function(log) {
            $scope.editService.log = log.Detail;
            $modalService.create({
                templateUrl: "view-log.html",
                model: $scope,
                title: "title_log",
                bigModal: true,
                actions: [
                    {
                        classes: "btn-default",
                        label: "download",
                        action: function(){
                            downloadFile('/services/' + running.ServiceID + '/' + running.ID + '/logs/download');
                        },
                        icon: "glyphicon-download"
                    },
                    {
                        role: "cancel",
                        classes: "btn-default",
                        label: "close"
                    }
                ],
                onShow: function(){
                    var textarea = this.$el.find("textarea");
                    textarea.scrollTop(textarea[0].scrollHeight - textarea.height());
                }
            });
        });
    };

    $scope.toggleRunning = toggleRunning;

    $scope.click_app = function(instance) {
        $location.path('/services/' + instance.ServiceID);
    };

    $scope.updateHost = function(){
        var modifiedHost = $.extend({}, $scope.hosts.current);
        resourcesService.update_host(modifiedHost.ID, modifiedHost, function() {
            refreshHosts($scope, resourcesService, false);
        });
    };

    refreshRunningForHost($scope, resourcesService, $scope.params.hostId);
    refreshHosts($scope, resourcesService, true, function() {
        if ($scope.hosts.current) {
            $scope.breadcrumbs.push({ label: $scope.hosts.current.Name, itemClass: 'active' });
        }
    });

    // Ensure we have a list of pools
    refreshPools($scope, resourcesService, false);

    resourcesService.get_stats(function(status) {
        if (status == 200) {
            $scope.collectingStats = true;
        } else {
            $scope.collectingStats = false;
        }
    });
}