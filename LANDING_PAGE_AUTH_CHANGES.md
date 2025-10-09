# Landing Page Authentication Changes

## Overview
This document showcases the changes made to the landing page beh**Reason:** The AppWrapperPage now shows the Landing page for **all users** (authenticated or not) when visiting `/`. Previously, it only showed the Landing page for unauthenticated users, and authenticated users would go through the nested routes which would eventually hit `CollectionIndexRedirect` that redirects to `/flows`.

### 2. Authentication Guard Changes
**File:** `src/frontend/src/components/authorization/authGuard/index.tsx`

**Change:**
```typescript
// BEFORE
const shouldRedirectHome =
  isOrgLoaded &&
  isAuthenticated &&
  isSignedIn &&
  isOrgSelected &&
  isRootPage;

// AFTER
const shouldRedirectHome = false; // Authenticated users stay on landing page
```

**Reason:** Additional safeguard to ensure authenticated users are not redirected from `/` to `/flows` by the auth guard.

### 5. Landing Page Header Changes
**File:** `src/frontend/src/pages/LandingPage/index.tsx`

**Added:**
- Import `useAuthStore` to check authentication status
- Import `useLogout` hook from `@/clerk/auth`
- Import `useNavigate` for navigation
- Created `AnimatedArrowIcon` component with framer-motion animation

**Header Logic:**
```tsx
{isAuthenticated ? (
  <>
    <button onClick={handleLogout}>Sign Out</button>
    <button onClick={handleDashboardClick}>
      Dashboard <AnimatedArrowIcon />
    </button>
  </>
) : (
  <>
    <a href="#demo">Book a Demo</a>
    <a href="/login">Log in</a>
  </>
)}
```

### 6. Animated Arrow Icon

### 3. Landing Page Header ChangesTH_ENABLED = true`.

## Previous Behavior

### Before Changes

**Unauthenticated User visiting `/`:**
- User stays on `/` (Landing Page)
- Header shows: `[Book a Demo]` `[Log in]`

**Authenticated User visiting `/`:**
- User is **automatically redirected** to `/flows`
- Landing page is not accessible to authenticated users

---

## New Behavior

### After Changes

### 1. Unauthenticated User visiting `/`

```
┌─────────────────────────────────────────────────────────────────┐
│  Visual AI Agents Builder                   [Book a Demo] [Log in]│
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Build AI Agents in Minutes.                                   │
│  Drag, Drop & Deploy Securely.                                 │
│                                                                 │
│  [Book a Demo]  [Watch the Demo]                               │
│                                                                 │
│  ... (rest of landing page content) ...                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Navigation:**
- ✅ User **stays on** `/` (no redirect)
- ✅ Top-right shows: `[Book a Demo]` `[Log in]`
- ✅ "Book a Demo" and "Watch the Demo" buttons below hero remain unchanged

**Interactions:**
- Clicking `[Log in]` → navigates to `/login`
- Clicking `[Book a Demo]` → scrolls to demo section

---

### 2. Authenticated User visiting `/`

```
┌─────────────────────────────────────────────────────────────────┐
│  Visual AI Agents Builder                   [Sign Out] [Dashboard >]│
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Build AI Agents in Minutes.                                   │
│  Drag, Drop & Deploy Securely.                                 │
│                                                                 │
│  [Book a Demo]  [Watch the Demo]                               │
│                                                                 │
│  ... (rest of landing page content) ...                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Navigation:**
- ✅ User **stays on** `/` (no auto-redirect to `/flows`)
- ✅ Top-right shows: `[Sign Out]` `[Dashboard >]`
  - `[Book a Demo]` → **replaced with** → `[Sign Out]`
  - `[Log in]` → **replaced with** → `[Dashboard >]` (with animated arrow)
- ✅ "Book a Demo" and "Watch the Demo" buttons below hero remain unchanged

**Interactions:**
- Clicking `[Sign Out]` → logs out the user using the same logout function from `/flows`
- Clicking `[Dashboard >]` → navigates to `/flows`
- The `>` icon is **animated** (moves right-left continuously)

---

## Visual Comparison

### Top-Right Header Buttons

| User State          | Before                        | After                              |
|---------------------|-------------------------------|------------------------------------|
| **Unauthenticated** | `[Book a Demo]` `[Log in]`    | `[Book a Demo]` `[Log in]`         |
| **Authenticated**   | N/A (redirected to `/flows`)  | `[Sign Out]` `[Dashboard >]`       |

### Landing Page Access

| User State          | Before                             | After                        |
|---------------------|------------------------------------|------------------------------|
| **Unauthenticated** | ✅ Can access `/` landing page     | ✅ Can access `/` landing page |
| **Authenticated**   | ❌ Auto-redirected to `/flows`     | ✅ Can access `/` landing page |

---

## Implementation Details

### 1. Clerk Auth Adapter - Remove Root Redirect
**File:** `src/frontend/src/clerk/auth.tsx`

**Change:**
```typescript
// BEFORE
const shouldRedirect =
  currentPath === "/" || currentPath === "/login" || currentPath === "/organization";

// AFTER
const shouldRedirect =
  currentPath === "/login" || currentPath === "/organization";
```

**Reason:** The `ClerkAuthAdapter` had a `useEffect` that redirected authenticated users away from "entry routes" including `/`. By removing `/` from this list, authenticated users can now remain on the landing page. The redirect still applies to `/login` and `/organization` pages since those are intermediate authentication steps.

### 2. ProtectedLoginRoute - Fix Redirect Destination
**File:** `src/frontend/src/components/authorization/authLoginGuard/index.tsx`

**Changes:**
```typescript
// BEFORE - Only applied to /login page
const isLoginPage = location.pathname.includes("login");
if (!isLoginPage) return children;
return <CustomNavigate to="/home" replace />;

// AFTER - Applied to both /login and /organization pages
const isLoginPage = location.pathname.includes("login");
const isOrgPage = location.pathname.includes("organization");
const shouldApplyGuard = isLoginPage || isOrgPage;
if (!shouldApplyGuard) return children;
return <CustomNavigate to="/flows" replace />;
```

**Reasons:** 
1. Fixed redirect from `/home` (non-existent) to `/flows`
2. Extended guard to cover `/organization` page so it also redirects to `/flows` after org selection
3. Added check for org selection in both store and session storage for reliability

### 3. AppWrapper Page Changes
**File:** `src/frontend/src/pages/AppWrapperPage/index.tsx`

**Change:**
```typescript
// BEFORE
if (!isAuthenticated && pathname === "/") {
  return <Landing />;
}

// AFTER
if (pathname === "/") {
  return <Landing />;
}
```

**Reason:** The AppWrapperPage now shows the Landing page for **all users** (authenticated or not) when visiting `/`. Previously, it only showed the Landing page for unauthenticated users, and authenticated users would go through the nested routes which would eventually hit `CollectionIndexRedirect` that redirects to `/flows`.

### 2. Authentication Guard Changes
**File:** `src/frontend/src/components/authorization/authGuard/index.tsx`

**Change:**
```typescript
// BEFORE
const shouldRedirectHome =
  isOrgLoaded &&
  isAuthenticated &&
  isSignedIn &&
  isOrgSelected &&
  isRootPage;

// AFTER
const shouldRedirectHome = false; // Authenticated users stay on landing page
```

### 2. Landing Page Header Changes
**File:** `src/frontend/src/pages/LandingPage/index.tsx`

**Added:**
- Import `useAuthStore` to check authentication status
- Import `useLogout` hook from `@/clerk/auth`
- Import `useNavigate` for navigation
- Created `AnimatedArrowIcon` component with framer-motion animation

**Header Logic:**
```tsx
{isAuthenticated ? (
  <>
    <button onClick={handleLogout}>Sign Out</button>
    <button onClick={handleDashboardClick}>
      Dashboard <AnimatedArrowIcon />
    </button>
  </>
) : (
  <>
    <a href="#demo">Book a Demo</a>
    <a href="/login">Log in</a>
  </>
)}
```

### 4. Animated Arrow Icon
The arrow icon (`>`) uses **Framer Motion** for smooth animation:

```tsx
<motion.svg 
  animate={{ x: [0, 4, 0] }}
  transition={{ 
    duration: 1.5, 
    repeat: Infinity, 
    ease: "easeInOut" 
  }}
>
  <path d="M8.59 16.59L13.17 12 8.59 7.41 10 6l6 6-6 6-1.41-1.41z" />
</motion.svg>
```

**Animation:** The arrow continuously moves 4px to the right and back, creating a subtle "forward" motion effect.

---

## User Flows

### Flow 1: Unauthenticated User Journey
```
1. User visits `/`
   ↓
2. Sees landing page with [Book a Demo] [Log in]
   ↓
3. Clicks [Log in]
   ↓
4. Redirected to `/login`
   ↓
5. After login → Redirected to `/flows`
```

### Flow 2: Authenticated User Journey
```
1. User visits `/`
   ↓
2. Sees landing page with [Sign Out] [Dashboard >]
   ↓
3a. Clicks [Dashboard >]
    → Navigates to `/flows`
    
3b. Clicks [Sign Out]
    → Logs out
    → Returns to landing page with [Book a Demo] [Log in]
```

---

## Notes

- ✅ All other navigation remains unchanged
- ✅ The "Book a Demo" and "Watch the Demo" buttons in the hero section remain visible for both authenticated and unauthenticated users
- ✅ The logout functionality uses the same `useLogout` hook as used in the `/flows` page
- ✅ The animated arrow provides a visual cue that the Dashboard button will take users to another page

---

## Testing Checklist

- [ ] Unauthenticated user can access `/` and sees `[Book a Demo]` `[Log in]`
- [ ] Authenticated user can access `/` and sees `[Sign Out]` `[Dashboard >]`
- [ ] Arrow icon in Dashboard button is animated
- [ ] Sign Out button logs out the user successfully
- [ ] Dashboard button navigates to `/flows`
- [ ] "Book a Demo" and "Watch the Demo" buttons in hero section remain unchanged
- [ ] Mobile responsive design works correctly
