<?php
// /var/www/schedule.permadomain.com/html/about.php
session_start();
require 'includes/db.php'; // Optional, only if dynamic content is added
require 'includes/functions.php'; // Optional, for debug_log or utilities

ini_set('display_errors', 0);
error_reporting(E_ALL);
?>

<?php include 'includes/header.php'; ?>
<style>
    .about-container {
        max-width: 900px;
        margin: 3rem auto;
        padding: 2.5rem;
        background: linear-gradient(135deg, #ffffff, #f8f9fa);
        border-radius: 15px;
        box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
        transition: transform 0.3s ease;
    }
    .about-container:hover {
        transform: translateY(-5px);
    }
    .about-container h1 {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1a3c66;
        text-align: center;
        margin-bottom: 1.5rem;
    }
    .about-container h2 {
        font-size: 1.8rem;
        font-weight: 600;
        color: #1a3c66;
        margin-top: 2rem;
        margin-bottom: 1rem;
    }
    .about-container p {
        font-size: 1rem;
        color: #374151;
        line-height: 1.6;
        margin-bottom: 1rem;
    }
    .about-container ul {
        list-style-type: disc;
        padding-left: 1.5rem;
        margin-bottom: 1.5rem;
    }
    .about-container ul li {
        font-size: 1rem;
        color: #374151;
        margin-bottom: 0.5rem;
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
    @media (max-width: 768px) {
        .about-container {
            margin: 1.5rem;
            padding: 1.5rem;
        }
        .about-container h1 {
            font-size: 1.8rem;
        }
        .about-container h2 {
            font-size: 1.5rem;
        }
    }
</style>

<div class="container my-5">
    <div class="about-container">
        <h1>Welcome to ScheduleMaster</h1>
        <p>ScheduleMaster is your all-in-one solution for creating, managing, and sharing schedules with ease. Whether you're organizing personal tasks, coordinating team events, or sharing plans with others, our platform offers a secure and user-friendly experience.</p>

        <h2>Why Choose ScheduleMaster?</h2>
        <p>Our service is designed to simplify scheduling while ensuring security and flexibility. With intuitive tools and robust admin controls, ScheduleMaster empowers users to stay organized and in control.</p>
        <ul>
            <li><strong>Easy Schedule Creation</strong>: Build and customize schedules in minutes.</li>
            <li><strong>Secure Profile Management</strong>: Update your username, email, and password with confidence.</li>
            <li><strong>Share with Ease</strong>: Generate read-only tokens to share schedules securely.</li>
            <li><strong>Admin Oversight</strong>: Admins can manage users and troubleshoot with our "Drop In" feature.</li>
            <li><strong>Responsive Design</strong>: Access your schedules on any device, anywhere.</li>
        </ul>

        <h2>Get Started Today</h2>
        <p>Join thousands of users who trust ScheduleMaster for their scheduling needs. Sign up now to create your first schedule or log in to manage your existing plans.</p>
        <div class="mt-4">
            <a href="/register.php" class="btn btn-primary me-2">Register Now</a>
            <a href="/login.php" class="btn btn-secondary">Log In</a>
        </div>

        <h2>Contact Us</h2>
        <p>Have questions or need support? Reach out to our team at <a href="mailto:support@schedule.permadomain.com">support@schedule.permadomain.com</a>.</p>
    </div>
</div>

<?php include 'includes/footer.php'; ?>
