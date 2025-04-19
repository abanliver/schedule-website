<?php
// /var/www/schedule.permadomain.com/html/admin/edit_user.php
session_start();
require '../includes/db.php';
require '../includes/functions.php';

// Disable display_errors in production
ini_set('display_errors', 0);
error_reporting(E_ALL);

// Log session state
debug_log("Session state: user_id=" . (isset($_SESSION['user_id']) ? $_SESSION['user_id'] : 'null') . ", is_admin=" . (isset($_SESSION['is_admin']) ? $_SESSION['is_admin'] : 'null'));

$userId = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$isAdmin = isset($_SESSION['is_admin']) && $_SESSION['is_admin'];

if (!$userId || !$isAdmin) {
    debug_log("Access denied: user_id=" . ($userId ?: 'null') . ", is_admin=" . ($isAdmin ? 'true' : 'false'));
    $_SESSION['error'] = 'Access denied. Admins only.';
    header('Location: /login.php');
    exit;
}

$editUserId = isset($_GET['id']) ? (int)$_GET['id'] : null;
if (!$editUserId) {
    debug_log("No user ID provided for editing: edit_user_id=" . ($editUserId ?: 'null'));
    $_SESSION['error'] = 'Invalid user ID.';
    header('Location: /admin/index.php');
    exit;
}

try {
    // Verify PDO connection
    if (!$pdo) {
        debug_log("PDO connection is null: edit_user_id=$editUserId");
        $_SESSION['error'] = 'Database connection failed.';
        header('Location: /admin/index.php');
        exit;
    }

    // Log query attempt
    debug_log("Attempting to fetch user: edit_user_id=$editUserId");
    $stmt = $pdo->prepare('SELECT id, username, email, is_admin FROM users WHERE id = ?');
    $stmt->execute([$editUserId]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Log query result
    debug_log("Query result for edit_user_id=$editUserId: " . ($user ? json_encode($user) : 'null'));

    // Check if user data is valid
    if (!$user || !isset($user['id'], $user['username'], $user['email'], $user['is_admin']) || empty($user['username']) || empty($user['email'])) {
        debug_log("Invalid or missing user data: edit_user_id=$editUserId, user=" . ($user ? json_encode($user) : 'null'));
        $_SESSION['error'] = 'User not found or invalid user data.';
        header('Location: /admin/index.php');
        exit;
    }
} catch (PDOException $e) {
    debug_log("Database error fetching user: edit_user_id=$editUserId, error=" . $e->getMessage());
    $_SESSION['error'] = 'Database error. Please try again.';
    header('Location: /admin/index.php');
    exit;
} catch (Exception $e) {
    debug_log("Unexpected error fetching user: edit_user_id=$editUserId, error=" . $e->getMessage());
    $_SESSION['error'] = 'Unexpected error. Please try again.';
    header('Location: /admin/index.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        debug_log("CSRF validation failed for edit_user_id=$editUserId");
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: /admin/index.php');
        exit;
    }

    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $isAdmin = isset($_POST['is_admin']) && $_POST['is_admin'] == '1' ? 1 : 0;

    // Validate inputs
    if (strlen($username) < 1 || strlen($username) > 255) {
        debug_log("Invalid username length: username=" . substr($username, 0, 50) . ", edit_user_id=$editUserId");
        $_SESSION['error'] = 'Username must be between 1 and 255 characters.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        debug_log("Invalid email format: email=" . substr($email, 0, 50) . ", edit_user_id=$editUserId");
        $_SESSION['error'] = 'Please enter a valid email address.';
    } elseif ($password && strlen($password) < 8) {
        debug_log("Password too short: edit_user_id=$editUserId");
        $_SESSION['error'] = 'Password must be at least 8 characters if provided.';
    } else {
        try {
            // Check for duplicate username (excluding current user)
            $stmt = $pdo->prepare('SELECT id FROM users WHERE username = ? AND id != ?');
            $stmt->execute([$username, $editUserId]);
            if ($stmt->fetch()) {
                debug_log("Duplicate username: username=" . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . ", edit_user_id=$editUserId");
                $_SESSION['error'] = 'Username already exists.';
            } else {
                // Check for duplicate email (excluding current user)
                $stmt = $pdo->prepare('SELECT id FROM users WHERE email = ? AND id != ?');
                $stmt->execute([$email, $editUserId]);
                if ($stmt->fetch()) {
                    debug_log("Duplicate email: email=" . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . ", edit_user_id=$editUserId");
                    $_SESSION['error'] = 'Email address already exists.';
                } else {
                    // Update user
                    $sql = 'UPDATE users SET username = ?, email = ?, is_admin = ?';
                    $params = [$username, $email, $isAdmin];
                    if ($password) {
                        $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                        $sql .= ', password = ?';
                        $params[] = $hashedPassword;
                    }
                    $sql .= ' WHERE id = ?';
                    $params[] = $editUserId;

                    $stmt = $pdo->prepare($sql);
                    $stmt->execute($params);
                    debug_log("User updated: user_id=$editUserId, username=" . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . ", email=" . htmlspecialchars($email, ENT_QUOTES, 'UTF-8') . ", is_admin=$isAdmin");
                    $_SESSION['success'] = 'User updated successfully.';
                    header('Location: /admin/index.php');
                    exit;
                }
            }
        } catch (PDOException $e) {
            debug_log("Database error updating user: edit_user_id=$editUserId, error=" . $e->getMessage());
            $_SESSION['error'] = 'Failed to update user. Please try again.';
        }
    }
    header('Location: /admin/index.php');
    exit;
}

// Log that we reached the form rendering stage
debug_log("Rendering form for edit_user_id=$editUserId, user=" . json_encode($user));
?>

<?php include '../includes/header.php'; 
var_dump($user);

?>
<style>
    .admin-container {
        max-width: 600px;
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
        font-size: 2rem;
        font-weight: 700;
        color: #1a3c66;
        text-align: center;
        margin-bottom: 2rem;
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
    .btn-primary, .btn-secondary {
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
    .alert {
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1.5rem;
        font-size: 0.95rem;
    }
    @media (max-width: 576px) {
        .admin-container {
            margin: 1.5rem;
            padding: 1.5rem;
        }
        .admin-container h1 {
            font-size: 1.75rem;
        }
    }
</style>

<div class="container my-5">
    <div class="admin-container">
        <h1>Edit User</h1>

        <?php if (isset($_SESSION['error'])): ?>
            <div class="alert alert-danger"><?php echo htmlspecialchars($_SESSION['error']); unset($_SESSION['error']); ?></div>
        <?php endif; ?>
        <?php if (isset($_SESSION['success'])): ?>
            <div class="alert alert-success"><?php echo htmlspecialchars($_SESSION['success']); unset($_SESSION['success']); ?></div>
        <?php endif; ?>

        <form method="POST" action="/admin/edit_user.php?id=<?php echo $editUserId; ?>">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="mb-4">
                <label for="username" class="form-label">Username</label>
                <input type="text" class="form-control" id="username" name="username" value="<?php echo htmlspecialchars($user['username']); ?>" required>
            </div>
            <div class="mb-4">
                <label for="email" class="form-label">Email</label>
                <input type="email" class="form-control" id="email" name="email" value="<?php echo htmlspecialchars($user['email']); ?>" required>
            </div>
            <div class="mb-4">
                <label for="password" class="form-label">New Password (leave blank to keep current)</label>
                <input type="password" class="form-control" id="password" name="password" placeholder="Enter new password">
            </div>
            <div class="mb-4 form-check">
                <input type="checkbox" class="form-check-input" id="is_admin" name="is_admin" value="1" <?php echo $user['is_admin'] ? 'checked' : ''; ?>>
                <label for="is_admin" class="form-check-label">Grant Admin Privileges</label>
            </div>
            <div class="d-flex justify-content-between">
                <button type="submit" class="btn btn-primary">Update User</button>
                <a href="/admin/index.php" class="btn btn-secondary">Cancel</a>
            </div>
        </form>
    </div>
</div>
<?php include '../includes/footer.php'; ?>
