import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Alert,
  Tooltip,
  TablePagination,
  Grid
} from '@mui/material';
import {
  Add,
  Edit,
  Delete,
  CheckCircle,
  Block,
  Visibility,
  Refresh,
  Download
} from '@mui/icons-material';
import api from '../services/api';
import { useAuth } from '../contexts/AuthContext';

const AIModels = () => {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [total, setTotal] = useState(0);
  const [openDialog, setOpenDialog] = useState(false);
  const [selectedModel, setSelectedModel] = useState(null);
  const [formData, setFormData] = useState({
    model_id: '',
    name: '',
    description: '',
    model_type: 'language_model',
    version: '',
    network_location: '',
    port: '',
    endpoint_path: '',
    allowed_operations: []
  });

  const { user, hasRole } = useAuth();

  useEffect(() => {
    fetchModels();
  }, [page, rowsPerPage]);

  const fetchModels = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/ai-models/?skip=${page * rowsPerPage}&limit=${rowsPerPage}`);
      setModels(response.data.models);
      setTotal(response.data.total);
    } catch (err) {
      setError('Failed to load AI models');
      console.error('AI Models error:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (modelId) => {
    try {
      await api.post(`/ai-models/${modelId}/approve`);
      fetchModels();
    } catch (err) {
      setError('Failed to approve AI model');
    }
  };

  const handleSuspend = async (modelId) => {
    try {
      await api.post(`/ai-models/${modelId}/suspend`, {
        reason: 'Administrative action'
      });
      fetchModels();
    } catch (err) {
      setError('Failed to suspend AI model');
    }
  };

  const handleDelete = async (modelId) => {
    if (window.confirm('Are you sure you want to delete this AI model?')) {
      try {
        await api.delete(`/ai-models/${modelId}`);
        fetchModels();
      } catch (err) {
        setError('Failed to delete AI model');
      }
    }
  };

  const handleSubmit = async () => {
    try {
      if (selectedModel) {
        // Update existing model
        await api.put(`/ai-models/${selectedModel.id}`, formData);
      } else {
        // Create new model
        await api.post('/ai-models/register', formData);
      }
      
      setOpenDialog(false);
      fetchModels();
      resetForm();
    } catch (err) {
      setError(selectedModel ? 'Failed to update AI model' : 'Failed to create AI model');
    }
  };

  const resetForm = () => {
    setFormData({
      model_id: '',
      name: '',
      description: '',
      model_type: 'language_model',
      version: '',
      network_location: '',
      port: '',
      endpoint_path: '',
      allowed_operations: []
    });
    setSelectedModel(null);
  };

  const openEditDialog = (model) => {
    setSelectedModel(model);
    setFormData({
      model_id: model.model_id,
      name: model.name,
      description: model.description || '',
      model_type: model.model_type,
      version: model.version,
      network_location: model.network_location,
      port: model.port?.toString() || '',
      endpoint_path: model.endpoint_path || '',
      allowed_operations: model.allowed_operations || []
    });
    setOpenDialog(true);
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'active': return 'success';
      case 'pending_approval': return 'warning';
      case 'suspended': return 'error';
      case 'inactive': return 'default';
      default: return 'default';
    }
  };

  const getTypeLabel = (type) => {
    return type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
  };

  return (
    <Box>
      <Box display="flex" justifyContent="space-between" alignItems="center" mb={3}>
        <Typography variant="h4">AI Models</Typography>
        {hasRole('ai_manager') && (
          <Button
            variant="contained"
            startIcon={<Add />}
            onClick={() => {
              resetForm();
              setOpenDialog(true);
            }}
          >
            Register AI Model
          </Button>
        )}
      </Box>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError('')}>
          {error}
        </Alert>
      )}

      <Paper>
        <TableContainer>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>Model ID</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Network Location</TableCell>
                <TableCell>Last Seen</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {models.map((model) => (
                <TableRow key={model.id}>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {model.model_id}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontWeight="bold">
                      {model.name}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      v{model.version}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={getTypeLabel(model.model_type)}
                      size="small"
                      variant="outlined"
                    />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={model.status.replace('_', ' ')}
                      color={getStatusColor(model.status)}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {model.network_location}
                      {model.port && `:${model.port}`}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2">
                      {model.last_seen 
                        ? new Date(model.last_seen).toLocaleString()
                        : 'Never'
                      }
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Box display="flex" gap={1}>
                      <Tooltip title="View Details">
                        <IconButton size="small">
                          <Visibility />
                        </IconButton>
                      </Tooltip>
                      
                      {hasRole('ai_manager') && (
                        <Tooltip title="Edit">
                          <IconButton size="small" onClick={() => openEditDialog(model)}>
                            <Edit />
                          </IconButton>
                        </Tooltip>
                      )}

                      {hasRole('admin') && model.status === 'pending_approval' && (
                        <Tooltip title="Approve">
                          <IconButton 
                            size="small" 
                            color="success"
                            onClick={() => handleApprove(model.id)}
                          >
                            <CheckCircle />
                          </IconButton>
                        </Tooltip>
                      )}

                      {hasRole('admin') && model.status === 'active' && (
                        <Tooltip title="Suspend">
                          <IconButton 
                            size="small" 
                            color="warning"
                            onClick={() => handleSuspend(model.id)}
                          >
                            <Block />
                          </IconButton>
                        </Tooltip>
                      )}

                      {hasRole('admin') && (
                        <Tooltip title="Delete">
                          <IconButton 
                            size="small" 
                            color="error"
                            onClick={() => handleDelete(model.id)}
                          >
                            <Delete />
                          </IconButton>
                        </Tooltip>
                      )}
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>

        <TablePagination
          component="div"
          count={total}
          page={page}
          onPageChange={(e, newPage) => setPage(newPage)}
          rowsPerPage={rowsPerPage}
          onRowsPerPageChange={(e) => {
            setRowsPerPage(parseInt(e.target.value, 10));
            setPage(0);
          }}
        />
      </Paper>

      {/* Add/Edit Dialog */}
      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="md" fullWidth>
        <DialogTitle>
          {selectedModel ? 'Edit AI Model' : 'Register New AI Model'}
        </DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Model ID"
                value={formData.model_id}
                onChange={(e) => setFormData({...formData, model_id: e.target.value})}
                fullWidth
                required
                disabled={selectedModel} // Can't change ID for existing models
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Name"
                value={formData.name}
                onChange={(e) => setFormData({...formData, name: e.target.value})}
                fullWidth
                required
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Description"
                value={formData.description}
                onChange={(e) => setFormData({...formData, description: e.target.value})}
                fullWidth
                multiline
                rows={2}
              />
            </Grid>
            <Grid item xs={12} sm={6}>
              <FormControl fullWidth required>
                <InputLabel>Model Type</InputLabel>
                <Select
                  value={formData.model_type}
                  onChange={(e) => setFormData({...formData, model_type: e.target.value})}
                  label="Model Type"
                >
                  <MenuItem value="language_model">Language Model</MenuItem>
                  <MenuItem value="vision_model">Vision Model</MenuItem>
                  <MenuItem value="audio_model">Audio Model</MenuItem>
                  <MenuItem value="multimodal">Multimodal</MenuItem>
                  <MenuItem value="embedding_model">Embedding Model</MenuItem>
                  <MenuItem value="classification">Classification</MenuItem>
                  <MenuItem value="generation">Generation</MenuItem>
                  <MenuItem value="custom">Custom</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} sm={6}>
              <TextField
                label="Version"
                value={formData.version}
                onChange={(e) => setFormData({...formData, version: e.target.value})}
                fullWidth
                required
              />
            </Grid>
            <Grid item xs={12} sm={8}>
              <TextField
                label="Network Location"
                value={formData.network_location}
                onChange={(e) => setFormData({...formData, network_location: e.target.value})}
                fullWidth
                required
                placeholder="IP address or hostname"
              />
            </Grid>
            <Grid item xs={12} sm={4}>
              <TextField
                label="Port"
                value={formData.port}
                onChange={(e) => setFormData({...formData, port: e.target.value})}
                fullWidth
                type="number"
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                label="Endpoint Path"
                value={formData.endpoint_path}
                onChange={(e) => setFormData({...formData, endpoint_path: e.target.value})}
                fullWidth
                placeholder="/v1/chat/completions"
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>Cancel</Button>
          <Button onClick={handleSubmit} variant="contained">
            {selectedModel ? 'Update' : 'Register'}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default AIModels;