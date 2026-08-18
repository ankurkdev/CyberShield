import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [backendConnected, setBackendConnected] = useState(false);
  const [alertFilter, setAlertFilter] = useState("ALL");
  const [logSearch, setLogSearch] = useState("");

  useEffect(() => {
    async function loadData() {
      try {
        const [alertsResponse, logsResponse] = await Promise.all([
          fetch("http://127.0.0.1:8000/alerts"),
          fetch("http://127.0.0.1:8000/logs"),
        ]);

        if (!alertsResponse.ok || !logsResponse.ok) {
          throw new Error("Backend request failed");
        }
        setBackendConnected(true);
  
        const alertsData = await alertsResponse.json();
        const logsData = await logsResponse.json();
  
        setAlerts(alertsData.alerts || []);
        setLogs(logsData.logs || []);
      } catch (error) {
        setBackendConnected(false);
        console.error("Failed to load CyberShield data:", error);
      } finally {
        setLoading(false);
      }
    }
  
    loadData();
  
    const refresh = setInterval(loadData, 5000);
  
    return () => clearInterval(refresh);
  }, []);

  async function updateAlertStatus(alertId, status) {
    try {
      const response = await fetch(
        `http://127.0.0.1:8000/alerts/${alertId}`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ status }),
        }
      );

      if (!response.ok) {
        throw new Error("Failed to update alert status");
      }

      const updatedAlert = await response.json();

      setAlerts((currentAlerts) =>
        currentAlerts.map((alert) =>
          alert.id === alertId ? updatedAlert : alert
        )
      );
    } catch (error) {
      console.error("Failed to update alert status:", error);
    }
  }

  const highSeverity = alerts.filter(
    (alert) => alert.severity === "HIGH"
  ).length;

  const newAlerts = alerts.filter(
    (alert) => alert.status === "NEW"
  ).length;

  const threatTypes = new Set(
    alerts.map((alert) => alert.threat_type)
  ).size;

  const threatSummary = alerts.reduce((summary, alert) => {
    summary[alert.threat_type] =
      (summary[alert.threat_type] || 0) + 1;
  
    return summary;
  }, {});

  const filteredAlerts =
  alertFilter === "ALL"
    ? alerts
    : alerts.filter((alert) => alert.status === alertFilter);
  
  const filteredLogs = logs.filter((log) => {
  const search = logSearch.toLowerCase();

  return (
    (log.ip_address || "").toLowerCase().includes(search) ||
    (log.username || "").toLowerCase().includes(search) ||
    (log.event_type || "").toLowerCase().includes(search) ||
    (log.request || "").toLowerCase().includes(search) ||
    (log.status || "").toLowerCase().includes(search)
  );
});

  return (
    <div className="dashboard">
      <header className="header">
        <div>
          <h1>CyberShield</h1>
          <p>Security Monitoring Dashboard</p>
        </div>

        <div className={`status ${backendConnected ? "connected" : "offline"}`}>
  <span></span>
  {backendConnected ? "Backend Connected" : "Backend Offline"}
</div>
      </header>

      <main>
        <div className="cards">
          <div className="card">
            <h3>Total Logs</h3>
            <strong>{logs.length}</strong>
          </div>

          <div className="card">
            <h3>Total Alerts</h3>
            <strong>{alerts.length}</strong>
          </div>

          <div className="card">
            <h3>High Severity</h3>
            <strong>{highSeverity}</strong>
          </div>

          <div className="card">
            <h3>New Alerts</h3>
            <strong>{newAlerts}</strong>
          </div>
        </div>

        <section className="panel">
          <div className="panel-header">
            <h2>Security Alerts</h2>
            <select
  value={alertFilter}
  onChange={(event) => setAlertFilter(event.target.value)}
>
  <option value="ALL">All</option>
  <option value="NEW">New</option>
  <option value="REVIEWED">Reviewed</option>
  <option value="RESOLVED">Resolved</option>
</select>
<span>{filteredAlerts.length} alerts</span>
          </div>

          {loading ? (
  <div className="message">Loading alerts...</div>
) : filteredAlerts.length === 0 ? (
  <div className="message">
    {alerts.length === 0
      ? "No threats detected."
      : "No alerts match this filter."}
  </div>
) : (
            <div className="alerts">
              {filteredAlerts.map((alert) => (
                <div className="alert" key={alert.id}>
                  <div className="severity">
                    {alert.severity}
                  </div>

                  <div className="alert-info">
                    <h3>{alert.threat_type}</h3>

                    <p>{alert.message}</p>

                    <small>
                      IP: {alert.ip_address}
                      {alert.username &&
                        ` • User: ${alert.username}`}
                    </small>
                  </div>

                  <div className="alert-status">
  <select
    value={alert.status}
    onChange={(event) =>
      updateAlertStatus(alert.id, event.target.value)
    }
  >
    <option value="NEW">NEW</option>
    <option value="REVIEWED">REVIEWED</option>
    <option value="RESOLVED">RESOLVED</option>
  </select>
</div>
                </div>
              ))}
            </div>
          )}
        </section>

<section className="panel">
  <div className="panel-header">
    <h2>Threat Summary</h2>
    <span>{threatTypes} types</span>
  </div>

  <div className="threat-summary">
    {Object.entries(threatSummary).map(([type, count]) => (
      <div className="threat-item" key={type}>
        <span>{type}</span>
        <strong>{count}</strong>
      </div>
    ))}
  </div>
</section>

<section className="panel">
  <div className="panel-header">
    <h2>Recent Logs</h2>
            <span>{filteredLogs.length} logs</span>
          </div>
          <input
  type="text"
  placeholder="Search IP, username, event, request..."
  value={logSearch}
  onChange={(event) => setLogSearch(event.target.value)}
  className="log-search"
/>

          {loading ? (
            <div className="message">Loading logs...</div>
          ) : (
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>IP Address</th>
                    <th>Event</th>
                    <th>Username</th>
                    <th>Status</th>
                    <th>Request</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredLogs.map((log) => (
                    <tr key={log.id}>
                      <td>{log.timestamp}</td>
                      <td>{log.ip_address}</td>
                      <td>{log.event_type}</td>
                      <td>{log.username || "-"}</td>
                      <td>{log.status || "-"}</td>
                      <td>{log.request || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default App;