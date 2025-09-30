import React, { useState, useEffect } from 'react';
import { Activity, Server, Network, AlertCircle, CheckCircle, XCircle, AlertTriangle, HelpCircle } from 'lucide-react';

const NMSMonitor = () => {
const [activeTab, setActiveTab] = useState('host');
const [hostData, setHostData] = useState(null);
const [snmpData, setSnmpData] = useState(null);
const [nmapData, setNmapData] = useState(null);
const [baseUrl, setBaseUrl] = useState('http://192.168.2.39:8080');
const [snmpSubnet, setSnmpSubnet] = useState('192.168.2.0/24');
const [nmapSubnet, setNmapSubnet] = useState('192.168.2.0/24');
const [nmapPorts, setNmapPorts] = useState('22,80,443');
const [loading, setLoading] = useState({ host: false, snmp: false, nmap: false });
const [lastUpdate, setLastUpdate] = useState({ host: null, snmp: null, nmap: null });

const [devices, setDevices] = useState([]);
const [loadingDevices, setLoadingDevices] = useState(false);
const [selectedDevice, setSelectedDevice] = useState(null);

// a list of candidate IPs (you can later generate this dynamically with a subnet input)
const fetchDevices = async () => {
setLoadingDevices(true);
try {
const res = await fetch(`${baseUrl}/discover_agents?subnet=192.168.2.0/24&port=8080`);
const data = await res.json();
const filteredDevices = data.devices.filter(d => !d.error);
setDevices(filteredDevices)

if (selectedDevice) {
  const updated = filteredDevices.find(d => d.ip === selectedDevice.ip);
  console.log("after fetch updated: ", updated);
  if (updated) {
    setSelectedDevice(updated);
    console.log("after fetch selected", selectedDevice);
  }
}

} catch (err) {
console.error("Failed to discover agents", err);
} finally {
setLoadingDevices(false);
}
};

useEffect(() => {
  if (selectedDevice) {
    console.log("Selected IP:", selectedDevice.ip);
  }
}, [selectedDevice]);

useEffect(() => {
fetchDevices();
const interval = setInterval(fetchDevices, 5000);
return () => clearInterval(interval);
}, [baseUrl]);

useEffect(() => {
  if (!selectedDevice) return;

  const updated = devices.find(d => d.ip === selectedDevice.ip);
  if (updated) {
    setSelectedDevice(updated);
  }
}, [devices]);

const fetchHostMetrics = async () => {
setLoading(prev => ({ ...prev, host: true }));
try {
const response = await fetch(`${baseUrl}/metrics`);
const data = await response.json();
setHostData(data);
setLastUpdate(prev => ({ ...prev, host: new Date() }));
} catch (error) {
console.error('Failed to fetch host metrics:', error);
} finally {
setLoading(prev => ({ ...prev, host: false }));
}
};

const fetchSNMP = async () => {
setLoading(prev => ({ ...prev, snmp: true }));
try {
const response = await fetch(`${baseUrl}/snmp_scan?subnet=${snmpSubnet}&community=public&concurrency=50&timeout=2s`);
const data = await response.json();
setSnmpData(data);
setLastUpdate(prev => ({ ...prev, snmp: new Date() }));
} catch (error) {
console.error('Failed to fetch SNMP data:', error);
} finally {
setLoading(prev => ({ ...prev, snmp: false }));
}
};

const fetchNmap = async () => {
setLoading(prev => ({ ...prev, nmap: true }));
try {
const response = await fetch(`${baseUrl}/nmap_scan?subnet=${nmapSubnet}&ports=${nmapPorts}&timeout=60s`);
const data = await response.json();
setNmapData(data);
setLastUpdate(prev => ({ ...prev, nmap: new Date() }));
} catch (error) {
console.error('Failed to fetch Nmap data:', error);
} finally {
setLoading(prev => ({ ...prev, nmap: false }));
}
};

useEffect(() => {
fetchHostMetrics();
const interval = setInterval(fetchHostMetrics, 5000);
return () => clearInterval(interval);
}, [baseUrl]);

const getStatusIcon = (status) => {
switch (status) {
case 'healthy': return
<CheckCircle className="w-5 h-5 text-green-500" />;
case 'warning': return
<AlertTriangle className="w-5 h-5 text-yellow-500" />;
case 'critical': return
<XCircle className="w-5 h-5 text-red-500" />;
case 'unknown': return
<HelpCircle className="w-5 h-5 text-gray-400" />;
default: return
<HelpCircle className="w-5 h-5 text-gray-400" />;
}
};

const getStatusColor = (status) => {
switch (status) {
case 'healthy': return 'bg-green-100 border-green-300';
case 'warning': return 'bg-yellow-100 border-yellow-300';
case 'critical': return 'bg-red-100 border-red-300';
case 'unknown': return 'bg-gray-100 border-gray-300';
default: return 'bg-gray-100 border-gray-300';
}
};

const formatUptime = (seconds) => {
const days = Math.floor(seconds / 86400);
const hours = Math.floor((seconds % 86400) / 3600);
const minutes = Math.floor((seconds % 3600) / 60);
return `${days}d ${hours}h ${minutes}m`;
};

const formatTime = (date) => {
if (!date) return 'Never';
return date.toLocaleTimeString();
};

return (
<div className="min-h-screen bg-gray-50 p-6">
    <div className="max-w-7xl mx-auto">
        <div className="bg-white rounded-lg shadow-lg p-6 mb-6">
            <h1 className="text-3xl font-bold text-gray-800 mb-2">NMS Agent Monitor</h1>
            <div className="flex items-center gap-4 text-sm text-gray-600">
                <div className="flex items-center gap-2">
                    <Activity className="w-4 h-4" />
                    <span>Real-time Network Monitoring</span>
                </div>
                <div className="flex items-center gap-2">
                    <input type="text" value={baseUrl} onChange={(e)=> setBaseUrl(e.target.value)}
                    className="px-3 py-1 border rounded text-sm"
                    placeholder="Base URL"
                    />
                </div>
            </div>
        </div>

        <div className="bg-white rounded-lg shadow-lg overflow-hidden">
            <div className="flex border-b">
                <button onClick={()=> setActiveTab('host')}
                    className={`flex items-center gap-2 px-6 py-4 font-medium transition-colors ${
                    activeTab === 'host'
                    ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                    }`}
                    >
                    <Server className="w-5 h-5" />
                    Host Monitoring
                </button>
                <button onClick={()=> setActiveTab('snmp')}
                    className={`flex items-center gap-2 px-6 py-4 font-medium transition-colors ${
                    activeTab === 'snmp'
                    ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                    }`}
                    >
                    <Network className="w-5 h-5" />
                    SNMP Devices
                </button>
                <button onClick={()=> setActiveTab('nmap')}
                    className={`flex items-center gap-2 px-6 py-4 font-medium transition-colors ${
                    activeTab === 'nmap'
                    ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                    }`}
                    >
                    <AlertCircle className="w-5 h-5" />
                    Port Scan
                </button>
                <button onClick={()=> setActiveTab('devices')}
                    className={`flex items-center gap-2 px-6 py-4 font-medium transition-colors ${
                    activeTab === 'devices'
                    ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
                    : 'text-gray-600 hover:bg-gray-50'
                    }`}
                    >
                    <Network className="w-5 h-5" />
                    Network Devices
                </button>
            </div>

            <div className="p-6">
                {activeTab === 'host' && (
                <div>
                    <div className="flex justify-between items-center mb-6">
                        <h2 className="text-xl font-semibold text-gray-800">Host System Status</h2>
                        <div className="flex items-center gap-3">
                            <span className="text-sm text-gray-500">Last update: {formatTime(lastUpdate.host)}</span>
                            <button onClick={fetchHostMetrics} disabled={loading.host}
                                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 text-sm">
                                {loading.host ? 'Loading...' : 'Refresh'}
                            </button>
                        </div>
                    </div>

                    {hostData ? (
                    <div className="space-y-6">
                        <div className={`border-2 rounded-lg p-6 ${getStatusColor(hostData.overall_status)}`}>
                            <div className="flex items-start justify-between">
                                <div>
                                    <h3 className="text-2xl font-bold text-gray-800 mb-2">{hostData.hostname}</h3>
                                    <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm text-gray-700">
                                        <div><span className="font-medium">OS:</span> {hostData.os}</div>
                                        <div><span className="font-medium">Platform:</span> {hostData.platform}</div>
                                        <div><span className="font-medium">Version:</span> {hostData.platform_version}
                                        </div>
                                        <div><span className="font-medium">Kernel:</span> {hostData.kernel}</div>
                                        <div className="col-span-2"><span className="font-medium">Uptime:</span>
                                            {formatUptime(hostData.uptime_seconds)}</div>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    {getStatusIcon(hostData.overall_status)}
                                    <span className="text-lg font-semibold capitalize">{hostData.overall_status}</span>
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {hostData.checks.map((check, idx) => (
                            <div key={idx} className={`border-2 rounded-lg p-4 ${getStatusColor(check.status)}`}>
                                <div className="flex items-start justify-between mb-2">
                                    <h4 className="font-semibold text-gray-800 capitalize">
                                      {check.name.replace(/_/g, ' ')}
                                    </h4>
                                    {getStatusIcon(check.status)}
                                </div>
                                <p className="text-sm text-gray-700">{check.message}</p>
                                {check.details && (
                                <pre className="mt-2 text-xs text-gray-600 bg-white bg-opacity-50 p-2 rounded overflow-x-auto">
                              {JSON.stringify(check.details, null, 2)}
                            </pre>
                                )}
                            </div>
                            ))}
                        </div>
                    </div>
                    ) : (
                    <div className="text-center py-12 text-gray-500">
                        {loading.host ? 'Loading host metrics...' : 'No data available'}
                    </div>
                    )}
                </div>
                )}

                {activeTab === 'snmp' && (
                <div>
                    <div className="mb-6">
                        <h2 className="text-xl font-semibold text-gray-800 mb-4">SNMP Device Discovery</h2>
                        <div className="flex gap-3 items-end">
                            <div className="flex-1">
                                <label className="block text-sm font-medium text-gray-700 mb-1">Subnet (CIDR)</label>
                                <input type="text" value={snmpSubnet} onChange={(e)=> setSnmpSubnet(e.target.value)}
                                className="w-full px-3 py-2 border rounded"
                                placeholder="192.168.1.0/24"
                                />
                            </div>
                            <button onClick={fetchSNMP} disabled={loading.snmp}
                                className="px-6 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50">
                                {loading.snmp ? 'Scanning...' : 'Scan'}
                            </button>
                        </div>
                        {lastUpdate.snmp && (
                        <p className="text-sm text-gray-500 mt-2">Last scan: {formatTime(lastUpdate.snmp)}</p>
                        )}
                    </div>

                    {snmpData ? (
                    <div className="space-y-4">
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <p className="text-sm">
                                <span className="font-semibold">{snmpData.devices.length}</span> devices found,{' '}
                                <span className="font-semibold">{snmpData.failed_count}</span> failed
                            </p>
                        </div>

                        <div className="space-y-3">
                            {snmpData.devices.map((device, idx) => (
                            <div key={idx}
                                className="border-2 border-gray-200 rounded-lg p-4 hover:border-blue-300 transition-colors">
                                <div className="flex items-start justify-between mb-3">
                                    <div>
                                        <h3 className="font-bold text-lg text-gray-800">{device.ip}</h3>
                                        {device.sys_name && (
                                        <p className="text-sm text-gray-600">{device.sys_name}</p>
                                        )}
                                    </div>
                                    <span
                                        className="px-3 py-1 bg-green-100 text-green-700 rounded-full text-xs font-medium">
                                        Active
                                    </span>
                                </div>

                                {device.sys_descr && (
                                <div className="mb-3">
                                    <p className="text-sm text-gray-700 bg-gray-50 p-2 rounded">{device.sys_descr}</p>
                                </div>
                                )}

                                <div className="grid grid-cols-2 gap-3 text-sm">
                                    {device.sys_object_id && (
                                    <div>
                                        <span className="font-medium text-gray-600">Object ID:</span>
                                        <p className="text-gray-800 font-mono text-xs">{device.sys_object_id}</p>
                                    </div>
                                    )}
                                    {device.open_ports && device.open_ports.length > 0 && (
                                    <div>
                                        <span className="font-medium text-gray-600">Open Ports:</span>
                                        <p className="text-gray-800">{device.open_ports.join(', ')}</p>
                                    </div>
                                    )}
                                </div>

                                {device.health && Object.keys(device.health).length > 0 && (
                                <div className="mt-3 pt-3 border-t">
                                    <p className="text-xs font-medium text-gray-600 mb-2">Health Metrics:</p>
                                    <div className="grid grid-cols-3 gap-2 text-xs">
                                        {Object.entries(device.health).map(([key, value]) => (
                                        <div key={key} className="bg-gray-50 p-2 rounded">
                                            <span className="text-gray-600">{key.replace(/_/g, ' ')}:</span>
                                            <p className="font-mono text-gray-800">{value}</p>
                                        </div>
                                        ))}
                                    </div>
                                </div>
                                )}
                            </div>
                            ))}
                        </div>
                    </div>
                    ) : (
                    <div className="text-center py-12 text-gray-500">
                        {loading.snmp ? 'Scanning network for SNMP devices...' : 'Enter subnet and click Scan'}
                    </div>
                    )}
                </div>
                )}

                {activeTab === 'nmap' && (
                <div>
                    <div className="mb-6">
                        <h2 className="text-xl font-semibold text-gray-800 mb-4">Network Port Scanner</h2>
                        <div className="flex gap-3 items-end">
                            <div className="flex-1">
                                <label className="block text-sm font-medium text-gray-700 mb-1">Subnet (CIDR)</label>
                                <input type="text" value={nmapSubnet} onChange={(e)=> setNmapSubnet(e.target.value)}
                                className="w-full px-3 py-2 border rounded"
                                placeholder="192.168.1.0/24"
                                />
                            </div>
                            <div className="w-48">
                                <label className="block text-sm font-medium text-gray-700 mb-1">Ports</label>
                                <input type="text" value={nmapPorts} onChange={(e)=> setNmapPorts(e.target.value)}
                                className="w-full px-3 py-2 border rounded"
                                placeholder="22,80,443"
                                />
                            </div>
                            <button onClick={fetchNmap} disabled={loading.nmap}
                                className="px-6 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50">
                                {loading.nmap ? 'Scanning...' : 'Scan'}
                            </button>
                        </div>
                        {lastUpdate.nmap && (
                        <p className="text-sm text-gray-500 mt-2">Last scan: {formatTime(lastUpdate.nmap)}</p>
                        )}
                    </div>

                    {nmapData ? (
                    <div className="space-y-4">
                        {nmapData.error && (
                        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                            <p className="text-sm text-yellow-800">{nmapData.error}</p>
                        </div>
                        )}

                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                            <p className="text-sm">
                                <span className="font-semibold">{nmapData.results.length}</span> hosts scanned
                            </p>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                            {nmapData.results.map((result, idx) => (
                            <div key={idx} className={`border-2 rounded-lg p-4 ${ result.open_ports &&
                                result.open_ports.length> 0
                                ? 'border-green-300 bg-green-50'
                                : 'border-gray-200 bg-gray-50'
                                }`}
                                >
                                <div className="flex items-center justify-between mb-2">
                                    <h3 className="font-bold text-gray-800">{result.ip}</h3>
                                    {result.open_ports && result.open_ports.length > 0 ? (
                                    <span
                                        className="px-2 py-1 bg-green-200 text-green-800 rounded text-xs font-medium">
                                        {result.open_ports.length} open
                                    </span>
                                    ) : (
                                    <span className="px-2 py-1 bg-gray-200 text-gray-600 rounded text-xs font-medium">
                                        No ports
                                    </span>
                                    )}
                                </div>
                                {result.open_ports && result.open_ports.length > 0 && (
                                <div className="flex flex-wrap gap-1">
                                    {result.open_ports.map((port) => (
                                    <span key={port}
                                        className="px-2 py-1 bg-white border border-green-300 rounded text-xs font-mono">
                                        {port}
                                    </span>
                                    ))}
                                </div>
                                )}
                                {result.error && (
                                <p className="text-xs text-red-600 mt-2">{result.error}</p>
                                )}
                            </div>
                            ))}
                        </div>
                    </div>
                    ) : (
                    <div className="text-center py-12 text-gray-500">
                        {loading.nmap ? 'Scanning network ports...' : 'Enter subnet and click Scan'}
                    </div>
                    )}
                </div>
                )}

                {activeTab === 'devices' && (
                <div>
                    <div className="mb-6">
                        <h2 className="text-xl font-semibold text-gray-800 mb-4">Discovered Devices</h2>
                        <div className="flex gap-3 items-end">
                            <button onClick={fetchDevices} disabled={loadingDevices}
                                className="px-6 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50">
                                {loadingDevices ? 'Scanning...' : 'Discover Devices'}
                            </button>
                        </div>
                    </div>

                    {selectedDevice ? (
                    // Selected Device Host Monitoring
                    <div className="mt-4">
                      <button
                        onClick={() => setSelectedDevice(null)}
                        className="mb-4 px-4 py-2 bg-gray-200 rounded hover:bg-gray-300"
                      >
                        Back to devices
                      </button>

                      <h3 className="text-lg font-semibold mb-4">
                        {selectedDevice.ip} Host Details
                      </h3>

                      {/* Show error if device unreachable */}
                      {selectedDevice.error ? (
                        <div className="border border-red-300 bg-red-50 text-red-700 rounded-lg p-4 mb-4">
                          <p className="font-medium">Error:</p>
                          <p className="text-sm">{selectedDevice.error}</p>
                        </div>
                      ) : (
                        selectedDevice.data && (
                          <div className="border rounded-lg p-4 bg-white shadow">
                            {/* Host Overview */}
                            <div
                              className={`border-2 rounded-lg p-6 ${getStatusColor(
                                selectedDevice.data?.overall_status
                              )}`}
                            >
                              <div className="flex items-start justify-between">
                                <div>
                                  <h3 className="text-2xl font-bold text-gray-800 mb-2">
                                    {selectedDevice.data?.hostname || "Unknown"}
                                  </h3>

                                  <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm text-gray-700">
                                    <div>
                                      <span className="font-medium">OS:</span>{" "}
                                      {selectedDevice.data?.os || "N/A"}
                                    </div>
                                    <div>
                                      <span className="font-medium">Platform:</span>{" "}
                                      {selectedDevice.data?.platform || "N/A"}
                                    </div>
                                    <div>
                                      <span className="font-medium">Version:</span>{" "}
                                      {selectedDevice.data?.platform_version || "N/A"}
                                    </div>
                                    <div>
                                      <span className="font-medium">Kernel:</span>{" "}
                                      {selectedDevice.data?.kernel || "N/A"}
                                    </div>
                                    <div className="col-span-2">
                                      <span className="font-medium">Uptime:</span>{" "}
                                      {selectedDevice.data?.uptime_seconds
                                        ? formatUptime(selectedDevice.data.uptime_seconds)
                                        : "N/A"}
                                    </div>
                                  </div>
                                </div>

                                <div className="flex items-center gap-3">
                                  {getStatusIcon(selectedDevice.data?.overall_status)}
                                  <span className="text-lg font-semibold capitalize">
                                    {selectedDevice.data?.overall_status || "Unknown"}
                                  </span>
                                </div>
                              </div>
                            </div>

                            {/* Health Checks */}
                            {selectedDevice.data?.checks?.length > 0 && (
                              <div className="mt-6">
                                <h4 className="text-md font-semibold mb-2">Health Checks</h4>
                                <ul className="space-y-2">
                                  {selectedDevice.data.checks.map((check, idx) => {
                                    const colors = {
                                      healthy: "bg-green-100 text-green-800",
                                      warning: "bg-yellow-100 text-yellow-800",
                                      critical: "bg-red-100 text-red-800",
                                      unknown: "bg-gray-100 text-gray-800",
                                    };
                                    return (
                                      <li
                                        key={idx}
                                        className="flex items-center justify-between border rounded p-2"
                                      >
                                        <span className="font-medium">{check.name.replace(/_/g, " ")}</span>
                                        <span className="text-sm text-gray-600 flex-1 px-3">
                                          {check.message}
                                        </span>
                                        <span
                                          className={`text-xs px-2 py-1 rounded-full ${colors[check.status]}`}
                                        >
                                          {check.status}
                                        </span>
                                      </li>
                                    );
                                  })}
                                </ul>
                              </div>
                            )}
                          </div>
                        )
                      )}
                    </div>
                  ) : (
                    // Devices Grid
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                      {devices.map((dev, idx) => {
                        const hostname = dev.data?.hostname || "Unknown";
                        const os = dev.data?.os || (dev.error ? "Unreachable" : "N/A");
                        const status = dev.data?.overall_status || (dev.error ? "down" : "unknown");

                        const statusColors = {
                          healthy: "bg-green-100 text-green-800",
                          warning: "bg-yellow-100 text-yellow-800",
                          critical: "bg-red-100 text-red-800",
                          down: "bg-gray-200 text-gray-600",
                          unknown: "bg-gray-100 text-gray-800",
                        };

                        return (
                          <div
                            key={idx}
                            className="border rounded-xl p-4 hover:shadow-lg cursor-pointer transition-transform transform hover:scale-105 bg-white"
                            onClick={() => {
                              setSelectedDevice(dev);
                              console.log("This is selected: ", JSON.stringify(dev.ip));
                            }}
                          >
                            <div className="flex items-center justify-between">
                              <h3 className="font-bold text-gray-800">{dev.ip}</h3>
                              <span className={`text-xs px-2 py-1 rounded-full ${statusColors[status]}`}>
                                {status}
                              </span>
                            </div>

                            <p className="text-sm text-gray-700 mt-1 truncate">{hostname}</p>
                            <p className="text-xs text-gray-500">{os}</p>

                            {dev.error && (
                              <p className="text-xs text-red-500 mt-2 line-clamp-2">{dev.error}</p>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
                )}
            </div>
        </div>
    </div>
</div>
);
};

export default NMSMonitor;
