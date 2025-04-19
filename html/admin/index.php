<?php
// /var/www/schedule.permadomain.com/html/admin/index.php
session_start();
require '../includes/db.php';
require '../includes/functions.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$isReadOnly = isset($_SESSION['read_only']) && $_SESSION['read_only'];
$isAdmin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'];

if (!$userId || $isReadOnly || !$isAdmin) {
    debug_log("Access denied: user_id=" . ($userId ?: 'null') . ", is_read_only=" . ($isReadOnly ? 'true' : 'false') . ", is_admin=" . ($isAdmin ? 'true' : 'false'));
    $_SESSION['error'] = 'Access denied. Admins only.';
    header('Location: /schedule.php' . ($isReadOnly && isset($_SESSION['read_only_schedule_id']) ? '?schedule_id=' . $_SESSION['read_only_schedule_id'] : ''));
    exit;
}

try {
    $stmt = $pdo->prepare('SELECT username FROM users WHERE id = ? AND is_admin = 1');
    $stmt->execute([$userId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        debug_log("Admin user not found: user_id=$userId");
        session_destroy();
        $_SESSION = [];
        $_SESSION['error'] = 'Admin access denied.';
        header('Location: /login.php');
        exit;
    }
    $username = $user['username'];

    $stmt = $pdo->prepare('SELECT id, username, email, is_admin FROM users ORDER BY username');
    $stmt->execute();
    $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
    debug_log("Fetched " . count($users) . " users for admin user_id=$userId");
} catch (PDOException $e) {
    debug_log("Database error: " . $e->getMessage());
    $_SESSION['error'] = 'Database error. Please try again.';
    header('Location: /login.php');
    exit;
}
?>

<?php include '../includes/header.php'; ?>
<style>
    .admin-container {
        max-width: 900px;
        margin: 3rem auto;
        padding: 2.5rem;
        background: linear-gradient(135deg, #ffffff, #f8f9fa);
        border-radius: 15px;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
        transition: transform 0.3s ease;
    }
    .admin-container:hover {
        transform: translateY(-5px);
    }
    .admin-container h1 {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1a3c66;
        text-align: center;
        margin-bottom: 2rem;
    }
    .admin-container h2 {
        font-size: 1.6rem;
        font-weight: 600;
        color: #374151;
        margin-top: 2rem;
        margin-bottom: 1.5rem;
    }
    .form-control {
        border-radius: 8px;
        border: 1px solid #d1d5db;
        padding: 0.75rem 1rem;
        font-size: 1rem;
        transition: all 0.3s ease;
    }
    .form-control:focus {
        border-color: #3b82f6;
        box-shadow: 0 0 8px rgba(59, 130, 246, 0.3);
        outline: none;
    }
    .form-label {
        font-weight: 600;
        color: #374151;
        margin-bottom: 0.5rem;
    }
    .form-check-label {
        font-weight: 500;
        color: #374151;
    }
    .btn-primary, .btn-secondary, .btn-danger, .btn-warning {
        padding: 0.75rem 1.5rem;
        border-radius: 8px;
        font-size: 1rem;
        font-weight: 600;
        transition: all 0.3s ease;
    }
    .btn-primary {
        background-color: #3b82f6;
        border: none;
    }
    .btn-primary:hover {
        background-color: #1d4ed8;
        transform: translateY(-2px);
    }
    .btn-secondary {
        background-color: #6b7280;
        border: none;
    }
    .btn-secondary:hover {
        background-color: #4b5563;
        transform: translateY(-2px);
    }
    .btn-danger {
        background-color: #ef4444;
        border: none;
    }
    .btn-danger:hover {
        background-color: #b91c1c;
        transform: translateY(-2px);
    }
    .btn-warning {
        background-color: #f59e0b;
        border: none;
    }
    .btn-warning:hover {
        background-color: #d97706;
        transform: translateY(-2px);
    }
    .table {
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    .table th, .table td {
        padding: 1rem;
        vertical-align: middle;
    }
    .table thead {
        background-color: #1a3c66;
        color: #ffffff;
    }
    .table tbody tr:hover {
        background-color: #f1f5f9;
    }
    .alert {
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1.5rem;
        font-size: 0.95rem;
    }
    .action-buttons form, .action-buttons a {
        margin-right: 0.5rem;
    }
    .btn-sm {
        padding: 0.5rem 1rem;
        font-size: 0.875rem;
    }
    @media (max-width: 768px) {
        .admin-container {
            margin: 1.5rem;
            padding: 1.5rem;
        }
        .admin-container h1 {
            font-size: 1.8rem;
        }
        .table {
            font-size: 0.9rem;
        }
    }
</style>

<div class="container my-5">
    <div class="admin-container">
        <h1>Admin Panel</h1>

        <?php if (isset($_SESSION['success'])): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
        <?php endif; ?>
        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
        <?php endif; ?>

        <h2>Create New User</h2>
        <form method="POST" action="/admin/create_user.php">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="mb-4">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" placeholder="Enter username" required>
            </div>
            <div class="mb-4">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" placeholder="Enter email" required>
            </div>
            <div class="mb-4">
                <label for="password" class="form-label">Password</label>
                <input type="password" class="form-control" id="password" name="password" placeholder="Enter password" required>
            </div>
            <div class="mb-4 form-check">
                <input type="checkbox" class="form-check-input" id="is_admin" name="is_admin" value="1">
                <label for="is_admin" class="form-check-label">Grant Admin Privileges</label>
            </div>
            <button type="submit" name="create_user" class="btn btn-primary">Create User</button>
        </form>

        <h2 class="mt-5">Manage Users</h2>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Email</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td><?php echo $user['id']; ?></td>
                        <td><?php echo htmlspecialchars($user['username']); ?></td>
                        <td><?php echo htmlspecialchars($user['email']); ?></td>
                        <td class="action-buttons">
                            <a href="/admin/edit_user.php?id=<?php echo $user['id']; ?>" class="btn btn-primary btn-sm">Edit</a>
                            <form method="POST" action="/admin/delete_user.php" class="d-inline" onsubmit="return confirm('Are you sure you want to delete this user?');">
                                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
                                <button type="submit" class="btn btn-danger btn-sm">Delete</button>
                            </form>
                            <?php if (!$user['is_admin']): ?>
                                <a href="/admin/login_as_user.php?user_id=<?php echo $user['id']; ?>" class="btn btn-warning btn-sm" onclick="return confirm('Drop into <?php echo htmlspecialchars($user['username']); ?>’s account?');">Drop In</a>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <div class="mt-4">
            <a href="/index.php" class="btn btn-secondary">Back to Schedules</a>
            <form method="POST" action="/logout.php" class="d-inline">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <button type="submit" name="logout" class="btn btn-danger">Logout</button>
            </form>
        </div>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
