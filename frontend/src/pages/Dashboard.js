import React, { useState, useEffect } from 'react';
import {
  Box,
  Grid,
  Paper,
  Typography,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
  Alert,
  CircularProgress,
  LinearProgress
} from '@mui/material';
import {
  People,
  SmartToy,
  Security,
  Warning,
  CheckCircle,
  Error,
  TrendingUp,
  Schedule
} from '@mui/icons-material';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import api from '../services/api';
import { useAuth } from '../contexts/AuthContext';

const Dashboard = () => {
  const [overview, setOverview] = useState(null);
  const [activity, setActivity] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const { user } = useAuth();

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      const [overviewRes, activityRes, alertsRes] = await Promise.all([
        api.get('/dashboard/overview'),
        api.get('/dashboard/activity?hours=24&limit=10'),
        api.get('/dashboard/security-alerts?days=7&limit=5')
      ]);

      setOverview(overviewRes.data);
      setActivity(activityRes.data);
      setAlerts(alertsRes.data);
    } catch (err) {
      setError('Failed to load dashboard data');
      console.error('Dashboard error:', err);
    } finally {
      setLoading(false);
    }
  };

  const getSystemHealth = () => {
    if (!overview) return 'Unknown';
    
    const { health_indicators } = overview;
    if (health_indicators?.database_healthy && health_indicators?.security_alerts < 5) {
      return 'Healthy';
    } else if (health_indicators?.security_alerts < 10) {
      return 'Warning';
    } else {
      return 'Critical';
    }
  };

  const getHealthColor = (health) => {
    switch (health) {
      case 'Healthy': return 'success';
      case 'Warning': return 'warning';
      case 'Critical': return 'error';
      default: return 'default';
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'error';
      case 'high': return 'warning';
      case 'medium': return 'info';
      case 'low': return 'success';
      default: return 'default';
    }
  };

  const getActionIcon = (action) => {
    switch (action) {
      case 'login': return <CheckCircle color="success" />;
      case 'logout': return <CheckCircle color="action" />;
      case 'write': return <TrendingUp color="primary" />;
      case 'delete': return <Warning color="warning" />;
      default: return <Security color="action" />;
    }
  };

  const CHART_COLORS = ['#8884d8', '#82ca9d', '#ffc658', '#ff7300', '#8dd1e1'];

  if (loading) {
    return (
      <Box display="flex" flexDirection="column" alignItems="center" mt={4}>
        <CircularProgress />
        <Typography sx={{ mt: 2 }}>Loading dashboard...</Typography>
      </Box>
    );
  }

  if (error) {
    return (
      <Alert severity="error" sx={{ mt: 2 }}>
        {error}
      </Alert>
    );
  }

  const systemHealth = getSystemHealth();
  const modelsData = overview?.breakdowns?.models_by_type ? 
    Object.entries(overview.breakdowns.models_by_type).map(([name, value]) => ({ name, value })) : [];
  const usersData = overview?.breakdowns?.users_by_role ? 
    Object.entries(overview.breakdowns.users_by_role).map(([name, value]) => ({ name, value })) : [];

  return (
    <Box>
      <Typography variant="h4" gutterBottom>
        Dashboard
      </Typography>
      
      <Typography variant="body1" color="text.secondary" gutterBottom>
        Welcome back, {user?.full_name}! Here's what's happening in your AI environment.
      </Typography>

      {/* System Health */}
      <Box sx={{ mb: 3 }}>
        <Chip
          icon={systemHealth === 'Healthy' ? <CheckCircle /> : <Warning />}
          label={`System Health: ${systemHealth}`}
          color={getHealthColor(systemHealth)}
          size="large"
        />
      </Box>

      {/* Overview Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <People color="primary" sx={{ mr: 2, fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Total Users
                  </Typography>
                  <Typography variant="h4">
                    {overview?.overview?.total_users || 0}
                  </Typography>
                  <Typography variant="body2" color="success.main">
                    {overview?.overview?.active_users || 0} active
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <SmartToy color="secondary" sx={{ mr: 2, fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    AI Models
                  </Typography>
                  <Typography variant="h4">
                    {overview?.overview?.total_ai_models || 0}
                  </Typography>
                  <Typography variant="body2" color="success.main">
                    {overview?.overview?.active_ai_models || 0} active
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Security color="warning" sx={{ mr: 2, fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Security Events
                  </Typography>
                  <Typography variant="h4">
                    {overview?.overview?.security_events || 0}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Last 7 days
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center">
                <Schedule color="info" sx={{ mr: 2, fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" gutterBottom>
                    Recent Activity
                  </Typography>
                  <Typography variant="h4">
                    {overview?.overview?.recent_audit_events || 0}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Last 24 hours
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* AI Models by Type Chart */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              AI Models by Type
            </Typography>
            {modelsData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={modelsData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" fill="#8884d8" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <Box display="flex" justifyContent="center" alignItems="center" height={300}>
                <Typography color="text.secondary">No AI models registered</Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Users by Role Chart */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Users by Role
            </Typography>
            {usersData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={usersData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {usersData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={CHART_COLORS[index % CHART_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <Box display="flex" justifyContent="center" alignItems="center" height={300}>
                <Typography color="text.secondary">No user data available</Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {/* Recent Activity */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Recent Activity
            </Typography>
            <List>
              {activity.slice(0, 8).map((item, index) => (
                <ListItem key={index}>
                  <ListItemIcon>
                    {getActionIcon(item.action)}
                  </ListItemIcon>
                  <ListItemText
                    primary={item.description}
                    secondary={new Date(item.timestamp).toLocaleString()}
                  />
                  <Chip
                    label={item.level}
                    size="small"
                    color={item.level === 'error' ? 'error' : 'default'}
                  />
                </ListItem>
              ))}
              {activity.length === 0 && (
                <ListItem>
                  <ListItemText
                    primary="No recent activity"
                    secondary="System activity will appear here"
                  />
                </ListItem>
              )}
            </List>
          </Paper>
        </Grid>

        {/* Security Alerts */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Security Alerts
            </Typography>
            <List>
              {alerts.slice(0, 6).map((alert, index) => (
                <ListItem key={index}>
                  <ListItemIcon>
                    <Error color="error" />
                  </ListItemIcon>
                  <ListItemText
                    primary={alert.description}
                    secondary={new Date(alert.created_at).toLocaleString()}
                  />
                  <Chip
                    label={alert.severity}
                    size="small"
                    color={getSeverityColor(alert.severity)}
                  />
                </ListItem>
              ))}
              {alerts.length === 0 && (
                <ListItem>
                  <ListItemIcon>
                    <CheckCircle color="success" />
                  </ListItemIcon>
                  <ListItemText
                    primary="No security alerts"
                    secondary="All systems secure"
                  />
                </ListItem>
              )}
            </List>
          </Paper>
        </Grid>
      </Grid>

      {/* Pending Approvals */}
      {overview?.overview?.pending_approvals > 0 && (
        <Paper sx={{ p: 3, mt: 3 }}>
          <Alert severity="info">
            <Typography variant="h6">
              Pending Approvals
            </Typography>
            <Typography>
              There are {overview.overview.pending_approvals} AI models waiting for approval.
            </Typography>
          </Alert>
        </Paper>
      )}
    </Box>
  );
};

export default Dashboard;