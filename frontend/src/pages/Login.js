import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Box,
  Paper,
  TextField,
  Button,
  Typography,
  Alert,
  Container,
  FormControlLabel,
  Checkbox,
  InputAdornment,
  IconButton
} from '@mui/material';
import { Visibility, VisibilityOff, Security } from '@mui/icons-material';
import { useAuth } from '../contexts/AuthContext';

const Login = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    mfa_code: '',
    remember: false
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showMFA, setShowMFA] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/dashboard';

  const handleChange = (e) => {
    const { name, value, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: name === 'remember' ? checked : value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const credentials = {
        username: formData.username,
        password: formData.password
      };

      if (showMFA && formData.mfa_code) {
        credentials.mfa_code = formData.mfa_code;
      }

      const result = await login(credentials);

      if (result.success) {
        navigate(from, { replace: true });
      } else {
        if (result.error === 'MFA code required') {
          setShowMFA(true);
        } else {
          setError(result.error);
        }
      }
    } catch (err) {
      setError('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container component="main" maxWidth="sm">
      <Box
        sx={{
          marginTop: 8,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
        }}
      >
        <Paper
          elevation={6}
          sx={{
            padding: 4,
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            width: '100%',
            bgcolor: 'background.paper'
          }}
        >
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              mb: 3
            }}
          >
            <Security sx={{ mr: 1, fontSize: 40, color: 'primary.main' }} />
            <Typography component="h1" variant="h4" color="primary">
              Enterprise AI IAM
            </Typography>
          </Box>

          <Typography component="h2" variant="h6" sx={{ mb: 3 }}>
            Sign in to your account
          </Typography>

          {error && (
            <Alert severity="error" sx={{ width: '100%', mb: 2 }}>
              {error}
            </Alert>
          )}

          <Box component="form" onSubmit={handleSubmit} sx={{ width: '100%' }}>
            <TextField
              margin="normal"
              required
              fullWidth
              id="username"
              label="Username or Email"
              name="username"
              autoComplete="username"
              autoFocus
              value={formData.username}
              onChange={handleChange}
              disabled={loading}
            />

            <TextField
              margin="normal"
              required
              fullWidth
              name="password"
              label="Password"
              type={showPassword ? 'text' : 'password'}
              id="password"
              autoComplete="current-password"
              value={formData.password}
              onChange={handleChange}
              disabled={loading}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                )
              }}
            />

            {showMFA && (
              <TextField
                margin="normal"
                required
                fullWidth
                name="mfa_code"
                label="MFA Code"
                id="mfa_code"
                value={formData.mfa_code}
                onChange={handleChange}
                disabled={loading}
                inputProps={{ maxLength: 6 }}
                helperText="Enter the 6-digit code from your authenticator app"
              />
            )}

            <FormControlLabel
              control={
                <Checkbox
                  name="remember"
                  checked={formData.remember}
                  onChange={handleChange}
                  color="primary"
                />
              }
              label="Remember me"
              sx={{ mt: 1 }}
            />

            <Button
              type="submit"
              fullWidth
              variant="contained"
              sx={{ mt: 3, mb: 2 }}
              disabled={loading}
            >
              {loading ? 'Signing In...' : 'Sign In'}
            </Button>
          </Box>

          <Box sx={{ mt: 2, textAlign: 'center' }}>
            <Typography variant="body2" color="text.secondary">
              Enterprise AI Identity and Access Management System
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
              Secure access for AI models and users
            </Typography>
          </Box>

          {/* Demo credentials notice */}
          <Box sx={{ mt: 3, p: 2, bgcolor: 'background.default', borderRadius: 1, width: '100%' }}>
            <Typography variant="body2" color="text.secondary" align="center">
              <strong>Demo Credentials:</strong><br />
              Username: admin<br />
              Password: AdminPassword123!
            </Typography>
          </Box>
        </Paper>
      </Box>
    </Container>
  );
};

export default Login;