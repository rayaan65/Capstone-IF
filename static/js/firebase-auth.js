// Firebase Authentication Module
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js";
import { 
    getAuth, 
    createUserWithEmailAndPassword, 
    signInWithEmailAndPassword, 
    onAuthStateChanged, 
    signOut,
    GoogleAuthProvider,
    signInWithPopup,
    signInWithRedirect,
    getRedirectResult,
    sendPasswordResetEmail
} from "https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js";

// Firebase configuration will be loaded from the server
let firebaseConfig = {};
let app;
let auth;
let googleProvider;
let isInitialized = false;

// Initialize Firebase with configuration from server
async function initializeFirebase() {
    if (isInitialized) {
        console.log("Firebase already initialized");
        return true;
    }
    
    try {
        console.log("Initializing Firebase...");
        const response = await fetch('/get-firebase-config');
        firebaseConfig = await response.json();
        console.log("Firebase config loaded:", firebaseConfig);
        
        // Initialize Firebase
        app = initializeApp(firebaseConfig);
        auth = getAuth(app);
        
        // Initialize Google provider
        googleProvider = new GoogleAuthProvider();
        googleProvider.addScope('profile');
        googleProvider.addScope('email');
        console.log("Google provider initialized");
        
        // Set up auth state listener
        setupAuthStateListener();
        
        // Check for redirect result (for Google sign-in)
        try {
            console.log("Checking for redirect result...");
            const result = await getRedirectResult(auth);
            if (result) {
                // User signed in after a redirect
                console.log("Signed in user after redirect:", result.user);
                await sendTokenToServer(await result.user.getIdToken());
            } else {
                console.log("No redirect result found");
            }
        } catch (error) {
            console.error("Error processing redirect result:", error);
        }
        
        isInitialized = true;
        console.log("Firebase initialization complete");
        return true;
    } catch (error) {
        console.error("Error initializing Firebase:", error);
        return false;
    }
}

// Listen for authentication state changes
function setupAuthStateListener() {
    console.log("Setting up auth state listener");
    onAuthStateChanged(auth, async (user) => {
        if (user) {
            // User is signed in
            console.log("User is signed in:", user.email);
            
            // Send the Firebase token to your server
            try {
                const token = await user.getIdToken();
                const result = await sendTokenToServer(token);
                
                if (result && result.success) {
                    // Update UI with user info from server
                    updateUIForAuthenticatedUser(result.user);
                } else {
                    // Token verification failed on server
                    console.error("Server rejected the token:", result ? result.error : "Unknown error");
                }
            } catch (error) {
                console.error("Error getting ID token:", error);
            }
        } else {
            // User is signed out
            console.log("User is signed out");
            updateUIForUnauthenticatedUser();
            
            // Check if we have a server-side session
            checkServerSession();
        }
    });
}

// Check if we have a server-side session
async function checkServerSession() {
    try {
        console.log("Checking server session...");
        const response = await fetch('/check_auth');
        const data = await response.json();
        
        if (data.authenticated) {
            // We have a server-side session but no Firebase auth
            console.log("Server session found:", data);
            // This can happen with custom authentication
            updateUIForAuthenticatedUser({
                email: data.user_id,
                displayName: data.name,
                photoURL: data.picture
            });
        } else {
            console.log("No server session found");
        }
    } catch (error) {
        console.error("Error checking server session:", error);
    }
}

// Send Firebase token to server for session management
async function sendTokenToServer(token) {
    try {
        console.log("Sending token to server...");
        const response = await fetch('/verify-firebase-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token }),
        });
        
        const data = await response.json();
        console.log("Server verification response:", data);
        return data;
    } catch (error) {
        console.error("Error sending token to server:", error);
        return { success: false, error: error.message };
    }
}

// Register a new user with email and password
async function registerUser(email, password) {
    try {
        console.log("Registering user:", email);
        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
        console.log("User registered successfully:", userCredential.user);
        return {
            success: true,
            user: userCredential.user
        };
    } catch (error) {
        console.error("Registration error:", error);
        
        // Handle specific Firebase errors
        let errorMessage = "Registration failed. Please try again.";
        
        switch (error.code) {
            case 'auth/email-already-in-use':
                errorMessage = "This email is already registered. Please use a different email or try logging in.";
                break;
            case 'auth/invalid-email':
                errorMessage = "Invalid email address. Please check your email and try again.";
                break;
            case 'auth/weak-password':
                errorMessage = "Password is too weak. Please use a stronger password.";
                break;
        }
        
        return {
            success: false,
            error: errorMessage
        };
    }
}

// Sign in existing user with email and password
async function loginUser(email, password) {
    try {
        console.log("Logging in user:", email);
        const userCredential = await signInWithEmailAndPassword(auth, email, password);
        console.log("User logged in successfully:", userCredential.user);
        return {
            success: true,
            user: userCredential.user
        };
    } catch (error) {
        console.error("Login error:", error);
        
        // Handle specific Firebase errors
        let errorMessage = "Login failed. Please check your credentials and try again.";
        
        switch (error.code) {
            case 'auth/invalid-email':
                errorMessage = "Invalid email address. Please check your email and try again.";
                break;
            case 'auth/user-disabled':
                errorMessage = "This account has been disabled. Please contact support.";
                break;
            case 'auth/user-not-found':
                errorMessage = "No account found with this email. Please register first.";
                break;
            case 'auth/wrong-password':
                errorMessage = "Incorrect password. Please try again.";
                break;
        }
        
        return {
            success: false,
            error: errorMessage
        };
    }
}

// Sign in with Google - using popup approach
async function signInWithGoogle() {
    console.log("Starting Google sign-in process");
    
    // Make sure Firebase is initialized
    if (!isInitialized) {
        console.log("Firebase not initialized, initializing now...");
        await initializeFirebase();
    }
    
    if (!googleProvider) {
        console.log("Google provider not initialized, creating now...");
        googleProvider = new GoogleAuthProvider();
        googleProvider.addScope('profile');
        googleProvider.addScope('email');
    }
    
    try {
        console.log("Attempting Google sign-in with popup...");
        // Use signInWithPopup for better mobile experience
        const result = await signInWithPopup(auth, googleProvider);
        
        // The signed-in user info
        const user = result.user;
        console.log("Google sign-in successful:", user);
        
        // Send token to server immediately
        try {
            console.log("Getting ID token for server verification...");
            const token = await user.getIdToken();
            await sendTokenToServer(token);
        } catch (tokenError) {
            console.error("Error sending token after Google sign-in:", tokenError);
        }
        
        return {
            success: true,
            user: user
        };
    } catch (error) {
        console.error("Google sign-in error:", error);
        
        // If popup is blocked or fails, try redirect method
        if (error.code === 'auth/popup-blocked' || error.code === 'auth/popup-closed-by-user') {
            try {
                console.log("Popup blocked or closed, trying redirect method...");
                await signInWithRedirect(auth, googleProvider);
                return { success: true, redirecting: true };
            } catch (redirectError) {
                console.error("Redirect error:", redirectError);
                return {
                    success: false,
                    error: "Google sign-in failed. Please try again or use email login."
                };
            }
        }
        
        // Handle other specific errors
        let errorMessage = "Google sign-in failed. Please try again or use email login.";
        
        switch (error.code) {
            case 'auth/account-exists-with-different-credential':
                errorMessage = "An account already exists with the same email address but different sign-in credentials. Try signing in using a different method.";
                break;
            case 'auth/cancelled-popup-request':
                errorMessage = "The sign-in process was cancelled. Please try again.";
                break;
            case 'auth/network-request-failed':
                errorMessage = "Network error. Please check your internet connection and try again.";
                break;
            case 'auth/unauthorized-domain':
                errorMessage = "This domain is not authorized for OAuth operations. Contact your administrator.";
                break;
        }
        
        return {
            success: false,
            error: errorMessage
        };
    }
}

// Sign out current user
async function logoutUser() {
    try {
        console.log("Logging out user...");
        // Sign out from Firebase
        await signOut(auth);
        
        // Also clear server session
        await fetch('/logout');
        
        console.log("Logout successful");
        return { success: true };
    } catch (error) {
        console.error("Logout error:", error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Send password reset email
async function resetPassword(email) {
    try {
        console.log("Sending password reset email to:", email);
        await sendPasswordResetEmail(auth, email);
        console.log("Password reset email sent");
        return { success: true };
    } catch (error) {
        console.error("Password reset error:", error);
        
        // Handle specific Firebase errors
        let errorMessage = "Failed to send password reset email. Please try again.";
        
        switch (error.code) {
            case 'auth/invalid-email':
                errorMessage = "Invalid email address. Please check your email and try again.";
                break;
            case 'auth/user-not-found':
                errorMessage = "No account found with this email.";
                break;
        }
        
        return {
            success: false,
            error: errorMessage
        };
    }
}

// Update UI based on authentication state
function updateUIForAuthenticatedUser(user) {
    console.log("Updating UI for authenticated user:", user);
    // Hide login/register buttons, show logout button
    const authButtons = document.querySelectorAll('.auth-btn');
    const logoutButtons = document.querySelectorAll('.logout-btn');
    const userDisplayElements = document.querySelectorAll('.user-display');
    
    authButtons.forEach(btn => btn.style.display = 'none');
    logoutButtons.forEach(btn => btn.style.display = 'block');
    
    // Update user display elements with user email
    userDisplayElements.forEach(element => {
        element.textContent = user.displayName || user.email;
        element.style.display = 'block';
    });
    
    // Update user avatar if available
    const userAvatars = document.querySelectorAll('.user-avatar');
    userAvatars.forEach(avatar => {
        if (user.photoURL) {
            avatar.src = user.photoURL;
            avatar.style.display = 'block';
        }
    });
}

function updateUIForUnauthenticatedUser() {
    console.log("Updating UI for unauthenticated user");
    // Show login/register buttons, hide logout button
    const authButtons = document.querySelectorAll('.auth-btn');
    const logoutButtons = document.querySelectorAll('.logout-btn');
    const userDisplayElements = document.querySelectorAll('.user-display');
    const userAvatars = document.querySelectorAll('.user-avatar');
    
    authButtons.forEach(btn => btn.style.display = 'block');
    logoutButtons.forEach(btn => btn.style.display = 'none');
    
    // Hide user display elements
    userDisplayElements.forEach(element => {
        element.style.display = 'none';
    });
    
    // Hide user avatars
    userAvatars.forEach(avatar => {
        avatar.style.display = 'none';
    });
}

// Get current user
function getCurrentUser() {
    return auth ? auth.currentUser : null;
}

// Check if user is authenticated
function isAuthenticated() {
    return (auth && auth.currentUser !== null) || document.cookie.includes('session=');
}

// Export functions for use in other scripts
export {
    initializeFirebase,
    registerUser,
    loginUser,
    logoutUser,
    signInWithGoogle,
    resetPassword,
    getCurrentUser,
    isAuthenticated
}; 