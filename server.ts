import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import fs from 'fs';
import cors from 'cors';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { createServer as createViteServer } from 'vite';
import { readDatabase, writeDatabase, CMSDatabase } from './server/db';
import { CMSProject, PhotoItem, VideoItem, ProfileSettings } from './server/types';
import { 
  getCloudinary, 
  isCloudinaryReady, 
  uploadImageToCloudinary, 
  uploadVideoToCloudinary, 
  deleteFromCloudinary 
} from './server/cloudinary';

const app = express();
const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cms-secret-jwt-key-for-anish-barai-portfolio';

// Create persistent uploads directories
const UPLOADS_ROOT = path.join(process.cwd(), 'uploads');
const UPLOADS_IMAGES = path.join(UPLOADS_ROOT, 'images');
const UPLOADS_VIDEOS = path.join(UPLOADS_ROOT, 'videos');

[UPLOADS_ROOT, UPLOADS_IMAGES, UPLOADS_VIDEOS].forEach((dir) => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
});

// Setup Multer Storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) {
      cb(null, UPLOADS_VIDEOS);
    } else {
      cb(null, UPLOADS_IMAGES);
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    const ext = path.extname(file.originalname).toLowerCase();
    const baseName = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9_-]/g, '_');
    cb(null, `${baseName}-${uniqueSuffix}${ext}`);
  }
});

const upload = multer({
  storage,
  limits: {
    fileSize: 150 * 1024 * 1024 // 150MB limit
  },
  fileFilter: (req, file, cb) => {
    const allowedImageTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'image/svg+xml'];
    const allowedVideoTypes = ['video/mp4', 'video/webm', 'video/quicktime', 'video/ogg', 'video/x-matroska'];
    
    if (allowedImageTypes.includes(file.mimetype) || allowedVideoTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${file.mimetype}. Please upload JPG, PNG, WEBP, MP4, WebM, or MOV.`));
    }
  }
});

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve Uploaded Files
app.use('/uploads', express.static(UPLOADS_ROOT, {
  maxAge: '30d',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.mp4') || filePath.endsWith('.webm')) {
      res.setHeader('Accept-Ranges', 'bytes');
    }
  }
}));

// Auth Middleware
interface AuthRequest extends Request {
  user?: { email: string };
}

function authenticateToken(req: AuthRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Authentication required. Please log in.' });
    return;
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || !decoded) {
      res.status(403).json({ error: 'Invalid or expired token. Please log in again.' });
      return;
    }
    req.user = decoded as { email: string };
    next();
  });
}

// -------------------------------------------------------------
// API ENDPOINTS
// -------------------------------------------------------------

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// 1. Auth: Login (Supports ADMIN_EMAIL & ADMIN_PASSWORD env vars or database admin)
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const inputEmail = (email || '').trim().toLowerCase();
    const inputPassword = String(password).trim();

    // Check against process.env ADMIN_EMAIL & ADMIN_PASSWORD first
    const envAdminEmail = (process.env.ADMIN_EMAIL || 'admin@anishbarai.com').trim().toLowerCase();
    const envAdminPassword = (process.env.ADMIN_PASSWORD || 'adminpassword123').trim();

    const isEnvMatch = (inputEmail === envAdminEmail) && (inputPassword === envAdminPassword);

    // Also check database admin password hash
    const db = readDatabase();
    const dbAdminEmail = db.admin.email.toLowerCase();
    const isDbEmailMatch = dbAdminEmail === inputEmail;
    const isDbPasswordMatch = isDbEmailMatch && bcrypt.compareSync(inputPassword, db.admin.passwordHash);

    if (!isEnvMatch && !isDbPasswordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const authenticatedEmail = isEnvMatch ? envAdminEmail : db.admin.email;
    const token = jwt.sign({ email: authenticatedEmail }, JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        email: authenticatedEmail,
        name: db.settings.name || 'Anish Barai',
        role: 'Owner/Admin'
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Cloudinary Status
app.get('/api/cloudinary/status', authenticateToken, (req: AuthRequest, res) => {
  const isReady = isCloudinaryReady();
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME || null;
  res.json({
    configured: isReady,
    cloudName: isReady ? cloudName : null,
    provider: isReady ? 'Cloudinary Media CDN' : 'Local Sandbox Storage'
  });
});

// 2. Auth: Current User Verification
app.get('/api/auth/me', authenticateToken, (req: AuthRequest, res) => {
  const db = readDatabase();
  res.json({
    user: {
      email: db.admin.email,
      name: db.settings.name || 'Anish Barai',
      role: 'Admin',
      lastUpdated: db.admin.updatedAt
    }
  });
});

// 3. Auth: Change Admin Password or Email
app.post('/api/auth/change-password', authenticateToken, (req: AuthRequest, res) => {
  try {
    const { currentPassword, newPassword, newEmail } = req.body;
    const db = readDatabase();

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current and new password are required' });
    }

    if (!bcrypt.compareSync(currentPassword, db.admin.passwordHash)) {
      return res.status(401).json({ error: 'Current password does not match' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters long' });
    }

    const salt = bcrypt.genSaltSync(10);
    db.admin.passwordHash = bcrypt.hashSync(newPassword, salt);
    if (newEmail && newEmail.includes('@')) {
      db.admin.email = newEmail.trim().toLowerCase();
    }
    db.admin.updatedAt = new Date().toISOString();

    writeDatabase(db);
    res.json({ success: true, message: 'Admin credentials updated successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Failed to update credentials' });
  }
});

// 4. Projects: Get All (Public returns only published, admin ?all=true returns all)
app.get('/api/projects', (req, res) => {
  try {
    const db = readDatabase();
    const showAll = req.query.all === 'true';
    
    let projects = [...db.projects];
    // Sort by sortOrder then date
    projects.sort((a, b) => (a.sortOrder ?? 0) - (b.sortOrder ?? 0));

    if (!showAll) {
      projects = projects.filter((p) => p.published !== false);
    }

    res.json(projects);
  } catch (error) {
    console.error('Get projects error:', error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// 5. Projects: Get Single by ID
app.get('/api/projects/:id', (req, res) => {
  try {
    const db = readDatabase();
    const project = db.projects.find((p) => p.id === req.params.id);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }
    res.json(project);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch project' });
  }
});

// 6. Projects: Create New (Auth required)
app.post('/api/projects', authenticateToken, (req: AuthRequest, res) => {
  try {
    const db = readDatabase();
    const body = req.body;

    if (!body.title || !body.category) {
      return res.status(400).json({ error: 'Title and category are required' });
    }

    const newId = body.id || `proj-${Date.now()}`;
    const maxSortOrder = db.projects.reduce((max, p) => Math.max(max, p.sortOrder || 0), -1);

    const newProject: CMSProject = {
      id: newId,
      title: body.title.trim(),
      category: body.category || 'Cinematic',
      subtitle: body.subtitle || '',
      description: body.description || '',
      thumbnail: body.thumbnail || 'https://images.unsplash.com/photo-1519741497674-611481863552?auto=format&fit=crop&w=1200&q=85',
      beforeGradingThumb: body.beforeGradingThumb || body.thumbnail || '',
      afterGradingThumb: body.afterGradingThumb || body.thumbnail || '',
      galleryImages: body.galleryImages || [body.thumbnail].filter(Boolean),
      videoUrl: body.videoUrl || 'https://commondatastorage.googleapis.com/gtv-videos-bucket/sample/ForBiggerBlazes.mp4',
      duration: body.duration || '2:30',
      client: body.client || 'Client',
      year: body.year || new Date().getFullYear().toString(),
      role: body.role || 'Lead Editor & Cinematographer',
      software: body.software && body.software.length > 0 ? body.software : ['Adobe Premiere Pro', 'Photoshop'],
      specs: body.specs || {
        resolution: '4K UHD (3840x2160)',
        fps: '24.00 fps',
        aspectRatio: '16:9 Cinematic',
        colorSpace: 'Rec.709',
        camera: 'Cinema Camera Rig'
      },
      tags: body.tags || [body.category, 'Color Grading', 'Editing'],
      metrics: body.metrics || 'High Client Satisfaction',
      featured: Boolean(body.featured),
      published: body.published !== false,
      sortOrder: maxSortOrder + 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    db.projects.push(newProject);
    writeDatabase(db);

    res.status(201).json(newProject);
  } catch (error) {
    console.error('Create project error:', error);
    res.status(500).json({ error: 'Failed to create project' });
  }
});

// 7. Projects: Update (Auth required)
app.put('/api/projects/:id', authenticateToken, (req: AuthRequest, res) => {
  try {
    const db = readDatabase();
    const index = db.projects.findIndex((p) => p.id === req.params.id);
    if (index === -1) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const existing = db.projects[index];
    const updated: CMSProject = {
      ...existing,
      ...req.body,
      id: existing.id, // Preserve ID
      updatedAt: new Date().toISOString()
    };

    db.projects[index] = updated;
    writeDatabase(db);

    res.json(updated);
  } catch (error) {
    console.error('Update project error:', error);
    res.status(500).json({ error: 'Failed to update project' });
  }
});

// 8. Projects: Delete (Auth required)
app.delete('/api/projects/:id', authenticateToken, (req: AuthRequest, res) => {
  try {
    const db = readDatabase();
    const initialLen = db.projects.length;
    db.projects = db.projects.filter((p) => p.id !== req.params.id);

    if (db.projects.length === initialLen) {
      return res.status(404).json({ error: 'Project not found' });
    }

    writeDatabase(db);
    res.json({ success: true, message: 'Project deleted successfully' });
  } catch (error) {
    console.error('Delete project error:', error);
    res.status(500).json({ error: 'Failed to delete project' });
  }
});

// 9. Projects: Toggle Publish Status
app.patch('/api/projects/:id/toggle-publish', authenticateToken, (req: AuthRequest, res) => {
  try {
    const db = readDatabase();
    const project = db.projects.find((p) => p.id === req.params.id);
    if (!project) {
      return res.status(404).json({ error: 'Project not found' });
    }

    project.published = !project.published;
    project.updatedAt = new Date().toISOString();

    writeDatabase(db);
    res.json({ success: true, published: project.published, project });
  } catch (error) {
    res.status(500).json({ error: 'Failed to toggle status' });
  }
});

// 10. Projects: Reorder
app.patch('/api/projects/reorder', authenticateToken, (req: AuthRequest, res) => {
  try {
    const { orderedIds } = req.body;
    if (!Array.isArray(orderedIds)) {
      return res.status(400).json({ error: 'orderedIds array is required' });
    }

    const db = readDatabase();
    orderedIds.forEach((id, index) => {
      const proj = db.projects.find((p) => p.id === id);
      if (proj) {
        proj.sortOrder = index;
      }
    });

    writeDatabase(db);
    res.json({ success: true, message: 'Projects reordered successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reorder projects' });
  }
});

// 11. Media Upload: Single Image (Uploads to Cloudinary if configured, or local fallback)
app.post('/api/upload/image', authenticateToken, upload.single('image'), async (req: AuthRequest, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No image file uploaded' });
    }

    let fileUrl = `/uploads/images/${req.file.filename}`;
    let storageType: 'cloudinary' | 'local' = 'local';
    let cloudinaryPublicId: string | undefined = undefined;

    // Check Cloudinary
    if (isCloudinaryReady()) {
      try {
        const cldResult = await uploadImageToCloudinary(req.file.path, {
          category: req.body.category || 'Portfolio',
          caption: req.body.caption || req.file.originalname,
          tags: [req.body.category || 'Portfolio', 'AnishBaraiPortfolio']
        });

        if (cldResult && cldResult.secure_url) {
          fileUrl = cldResult.secure_url;
          storageType = 'cloudinary';
          cloudinaryPublicId = cldResult.public_id;
        }
      } catch (cldErr) {
        console.warn('Cloudinary upload warning, fallback to local storage:', cldErr);
      }
    }

    const db = readDatabase();
    const photoItem: PhotoItem = {
      id: `photo-${Date.now()}`,
      url: fileUrl,
      name: req.file.originalname,
      size: req.file.size,
      mimeType: req.file.mimetype,
      category: req.body.category || 'Portfolio',
      caption: req.body.caption || req.file.originalname,
      createdAt: new Date().toISOString(),
      storage: storageType,
      cloudinaryPublicId
    };

    db.photos.unshift(photoItem);
    writeDatabase(db);

    res.status(201).json({
      url: fileUrl,
      item: photoItem,
      storage: storageType,
      message: storageType === 'cloudinary' ? 'Uploaded to Cloudinary CDN successfully' : 'Saved locally'
    });
  } catch (error: any) {
    console.error('Image upload error:', error);
    res.status(500).json({ error: error.message || 'Image upload failed' });
  }
});

// 12. Media Upload: Multiple Gallery Images (Uploads to Cloudinary if configured)
app.post('/api/upload/gallery', authenticateToken, upload.array('images', 10), async (req: AuthRequest, res) => {
  try {
    const files = req.files as Express.Multer.File[];
    if (!files || files.length === 0) {
      return res.status(400).json({ error: 'No images uploaded' });
    }

    const db = readDatabase();
    const uploadedPhotos: PhotoItem[] = [];

    for (const file of files) {
      let fileUrl = `/uploads/images/${file.filename}`;
      let storageType: 'cloudinary' | 'local' = 'local';
      let cloudinaryPublicId: string | undefined = undefined;

      if (isCloudinaryReady()) {
        try {
          const cldResult = await uploadImageToCloudinary(file.path, {
            category: 'Gallery',
            tags: ['Gallery', 'AnishBaraiPortfolio']
          });
          if (cldResult && cldResult.secure_url) {
            fileUrl = cldResult.secure_url;
            storageType = 'cloudinary';
            cloudinaryPublicId = cldResult.public_id;
          }
        } catch (cldErr) {
          console.warn('Cloudinary upload warning for file', file.originalname, cldErr);
        }
      }

      const item: PhotoItem = {
        id: `photo-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
        url: fileUrl,
        name: file.originalname,
        size: file.size,
        mimeType: file.mimetype,
        category: 'Gallery',
        caption: file.originalname,
        createdAt: new Date().toISOString(),
        storage: storageType,
        cloudinaryPublicId
      };

      db.photos.unshift(item);
      uploadedPhotos.push(item);
    }

    writeDatabase(db);

    res.status(201).json({
      urls: uploadedPhotos.map((p) => p.url),
      photos: uploadedPhotos
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message || 'Gallery upload failed' });
  }
});

// 13. Media Upload: Video (Uploads to Cloudinary if configured)
app.post('/api/upload/video', authenticateToken, upload.single('video'), async (req: AuthRequest, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No video file uploaded' });
    }

    let fileUrl = `/uploads/videos/${req.file.filename}`;
    let storageType: 'cloudinary' | 'local' = 'local';
    let cloudinaryPublicId: string | undefined = undefined;
    let posterUrl = req.body.posterUrl || '';

    if (isCloudinaryReady()) {
      try {
        const cldResult = await uploadVideoToCloudinary(req.file.path, {
          title: req.file.originalname
        });
        if (cldResult && cldResult.secure_url) {
          fileUrl = cldResult.secure_url;
          storageType = 'cloudinary';
          cloudinaryPublicId = cldResult.public_id;
          if (!posterUrl && cldResult.public_id) {
            posterUrl = `https://res.cloudinary.com/${process.env.CLOUDINARY_CLOUD_NAME}/video/upload/${cldResult.public_id}.jpg`;
          }
        }
      } catch (cldErr) {
        console.warn('Cloudinary video upload warning, fallback to local storage:', cldErr);
      }
    }

    const db = readDatabase();
    const videoItem: VideoItem = {
      id: `video-${Date.now()}`,
      url: fileUrl,
      name: req.file.originalname,
      size: req.file.size,
      mimeType: req.file.mimetype,
      duration: req.body.duration || '0:30',
      posterUrl,
      format: req.file.mimetype,
      createdAt: new Date().toISOString(),
      storage: storageType,
      cloudinaryPublicId
    };

    db.videos.unshift(videoItem);
    writeDatabase(db);

    res.status(201).json({
      url: fileUrl,
      item: videoItem,
      storage: storageType,
      message: storageType === 'cloudinary' ? 'Uploaded to Cloudinary CDN successfully' : 'Saved locally'
    });
  } catch (error: any) {
    console.error('Video upload error:', error);
    res.status(500).json({ error: error.message || 'Video upload failed' });
  }
});

// 14. Media Library: Photos
app.get('/api/photos', (req, res) => {
  try {
    const db = readDatabase();
    res.json(db.photos || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch photos' });
  }
});

app.delete('/api/photos/:id', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const db = readDatabase();
    const photo = db.photos.find((p) => p.id === req.params.id);
    if (photo) {
      if (photo.cloudinaryPublicId) {
        await deleteFromCloudinary(photo.cloudinaryPublicId, 'image');
      }
      if (photo.url.startsWith('/uploads/images/')) {
        const localPath = path.join(process.cwd(), photo.url);
        if (fs.existsSync(localPath)) {
          try { fs.unlinkSync(localPath); } catch (e) { /* ignore */ }
        }
      }
    }
    db.photos = db.photos.filter((p) => p.id !== req.params.id);
    writeDatabase(db);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete photo' });
  }
});

// 15. Media Library: Videos
app.get('/api/videos', (req, res) => {
  try {
    const db = readDatabase();
    res.json(db.videos || []);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

app.delete('/api/videos/:id', authenticateToken, async (req: AuthRequest, res) => {
  try {
    const db = readDatabase();
    const video = db.videos.find((v) => v.id === req.params.id);
    if (video) {
      if (video.cloudinaryPublicId) {
        await deleteFromCloudinary(video.cloudinaryPublicId, 'video');
      }
      if (video.url.startsWith('/uploads/videos/')) {
        const localPath = path.join(process.cwd(), video.url);
        if (fs.existsSync(localPath)) {
          try { fs.unlinkSync(localPath); } catch (e) { /* ignore */ }
        }
      }
    }
    db.videos = db.videos.filter((v) => v.id !== req.params.id);
    writeDatabase(db);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// 16. Settings: Get & Update
app.get('/api/settings', (req, res) => {
  try {
    const db = readDatabase();
    res.json(db.settings);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/settings', authenticateToken, (req: AuthRequest, res) => {
  try {
    const db = readDatabase();
    db.settings = {
      ...db.settings,
      ...req.body
    };
    writeDatabase(db);
    res.json({ success: true, settings: db.settings });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// 17. Overview Stats
app.get('/api/stats/overview', authenticateToken, (req: AuthRequest, res) => {
  try {
    const db = readDatabase();
    const totalProjects = db.projects.length;
    const publishedProjects = db.projects.filter((p) => p.published !== false).length;
    const draftProjects = totalProjects - publishedProjects;
    const totalPhotos = db.photos.length;
    const totalVideos = db.videos.length;

    res.json({
      totalProjects,
      publishedProjects,
      draftProjects,
      totalPhotos,
      totalVideos,
      lastUpdated: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to calculate stats' });
  }
});

// 18. Database Reset (Restores default seeds)
app.post('/api/database/reset', authenticateToken, (req: AuthRequest, res) => {
  try {
    const dbPath = path.join(process.cwd(), 'data', 'cms-database.json');
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
    const freshDb = readDatabase();
    res.json({ success: true, message: 'Database reset to default seed data successfully', data: freshDb });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset database' });
  }
});

// -------------------------------------------------------------
// Vite Middleware / Static Production Serving
// -------------------------------------------------------------
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`FrameCraft CMS Server running on http://localhost:${PORT}`);
  });
}

startServer();
