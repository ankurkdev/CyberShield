import { useEffect, useState } from "react";
import "./App.css";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [backendConnected, setBackendConnected] = useState(false);
  const [backendError, setBackendError] = useState("");
  const [analytics, setAnalytics] = useState(null);
  const [alertFilter, setAlertFilter] = useState("ALL");
  const [logSearch, setLogSearch] = useState("");

  useEffect(() => {
    async function loadData() {
      try {
        const [alertsResponse, logsResponse, analyticsResponse] =
  await Promise.all([
    fetch("http://127.0.0.1:8000/alerts"),
    fetch("http://127.0.0.1:8000/logs"),
    fetch("http://127.0.0.1:8000/analytics"),
  ]);

  if (
    !alertsResponse.ok ||
    !logsResponse.ok ||
    !analyticsResponse.ok
  ) {
          throw new Error("Backend request failed");
        }
        setBackendConnected(true);
        setBackendError("");
  
        const alertsData = await alertsResponse.json();
        const logsData = await logsResponse.json();
        const analyticsData = await analyticsResponse.json();
  
        setAlerts(alertsData.alerts || []);
        setLogs(logsData.logs || []);
        setAnalytics(analyticsData);
      } catch (error) {
        setBackendConnected(false);
        setBackendError("Unable to connect to the CyberShield backend.");
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

  const highSeverity = analytics?.severity?.HIGH || 0;

const newAlerts = analytics?.alert_status?.NEW || 0;

const reviewedAlerts = analytics?.alert_status?.REVIEWED || 0;

const resolvedAlerts = analytics?.alert_status?.RESOLVED || 0;

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
      {backendError && (
  <div className="message backend-error">
    {backendError}
  </div>
)}
        <div className="cards">
          <div className="card">
            <h3>Total Logs</h3>
            <strong>{analytics?.total_logs || 0}</strong>
          </div>

          <div className="card">
            <h3>Total Alerts</h3>
            <strong>{analytics?.total_alerts || 0}</strong>
          </div>

          <div className="card">
            <h3>High Severity</h3>
            <strong>{highSeverity}</strong>
          </div>

          <div className="card">
            <h3>New Alerts</h3>
            <strong>{newAlerts}</strong>
          </div>

          <div className="card">
  <h3>Reviewed Alerts</h3>
  <strong>{reviewedAlerts}</strong>
</div>

<div className="card">
  <h3>Resolved Alerts</h3>
  <strong>{resolvedAlerts}</strong>
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
                  <div className={`severity severity-${alert.severity.toLowerCase()}`}>
  {alert.severity}
</div>

                  <div className="alert-info">
                    <h3>{alert.threat_type}</h3>

                    <p>{alert.message}</p>

                    <small>
  IP: {alert.ip_address}
  {alert.username &&
    ` • User: ${alert.username}`}
  {alert.detected_at &&
    ` • Detected: ${new Date(alert.detected_at).toLocaleString()}`}
</small>
                  </div>

                  <div className="alert-status">
                  <select
  className={`alert-status-select status-${alert.status.toLowerCase()}`}
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
      <div className="threat-label">
        <span>{type}</span>
        <strong>{count}</strong>
      </div>

      <div className="threat-bar">
        <div
          className="threat-bar-fill"
          style={{
            width: `${(count / alerts.length) * 100}%`,
          }}
        ></div>
      </div>
    </div>
  ))}
</div>
</section>

<section className="panel">
  <div className="panel-header">
    <h2>Threat Analytics</h2>
    <span>
      {analytics
        ? Object.keys(analytics.threat_types || {}).length
        : 0} types
    </span>
  </div>

  <div className="threat-analytics">
    {Object.entries(analytics?.threat_types || {}).map(
      ([type, count]) => {
        const total = analytics?.total_alerts || 1;
        const percentage = (count / total) * 100;

        return (
          <div className="analytics-item" key={type}>
            <div className="analytics-label">
              <span>{type}</span>
              <strong>{count}</strong>
            </div>

            <div className="analytics-bar">
              <div
                className="analytics-bar-fill"
                style={{ width: `${percentage}%` }}
              ></div>
            </div>

            <small>{percentage.toFixed(0)}% of alerts</small>
          </div>
        );
      }
    )}
  </div>
</section>

<section className="panel">
  <div className="panel-header">
    <h2>Top Attacking IPs</h2>
    <span>Top 10</span>
  </div>

  <div className="ip-analytics">
    {Object.entries(analytics?.top_ips || {}).length === 0 ? (
      <div className="message">
        No attacking IPs detected.
      </div>
    ) : (
      Object.entries(analytics?.top_ips || {}).map(
        ([ip, count]) => {
          const total = analytics?.total_alerts || 1;
          const percentage = (count / total) * 100;

          return (
            <div className="ip-item" key={ip}>
              <div className="ip-label">
                <span>{ip}</span>
                <strong>{count} alerts</strong>
              </div>

              <div className="ip-bar">
                <div
                  className="ip-bar-fill"
                  style={{ width: `${percentage}%` }}
                ></div>
              </div>
            </div>
          );
        }
      )
    )}
  </div>
</section>

<section className="panel">
  <div className="panel-header">
    <h2>Threat Activity</h2>
    <span>
      {analytics?.activity_over_time?.length || 0} days
    </span>
  </div>

  <div className="activity-chart">
    {analytics?.activity_over_time?.length === 0 ? (
      <div className="message">
        No threat activity available.
      </div>
    ) : (
      analytics?.activity_over_time?.map((item) => {
        const maxAlerts = Math.max(
          ...analytics.activity_over_time.map(
            (entry) => entry.alerts
          )
        );

        const percentage =
          maxAlerts > 0
            ? (item.alerts / maxAlerts) * 100
            : 0;

        return (
          <div className="activity-item" key={item.date}>
            <div className="activity-label">
              <span>{item.date}</span>
              <strong>{item.alerts} alerts</strong>
            </div>

            <div className="activity-bar">
              <div
                className="activity-bar-fill"
                style={{ width: `${percentage}%` }}
              ></div>
            </div>
          </div>
        );
      })
    )}
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
) : filteredLogs.length === 0 ? (
  <div className="message">
    {logs.length === 0
      ? "No logs available."
      : "No logs match your search."}
  </div>
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
                      <td>
  {log.timestamp
    ? new Date(log.timestamp).toLocaleString()
    : "-"}
</td>
                      <td>{log.ip_address}</td>
                      <td>{log.event_type}</td>
                      <td>{log.username || "-"}</td>
                      <td>
  {log.status ? (
    <span
      className={`log-status log-status-${log.status.toLowerCase()}`}
    >
      {log.status}
    </span>
  ) : (
    "-"
  )}
</td>
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