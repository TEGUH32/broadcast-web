// Global JavaScript Utilities untuk semua halaman

const Utils = {
    // Format tanggal
    formatDate: (date, format = 'id-ID') => {
        const d = new Date(date);
        const options = {
            year: 'numeric',
            month: 'long',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        };
        return d.toLocaleDateString(format, options);
    },

    // Format angka (ribuan separator)
    formatNumber: (num) => {
        return new Intl.NumberFormat('id-ID').format(num);
    },

    // Format waktu relatif
    timeAgo: (date) => {
        const now = new Date();
        const past = new Date(date);
        const diff = now - past;
        
        const minute = 60 * 1000;
        const hour = minute * 60;
        const day = hour * 24;
        const week = day * 7;
        const month = day * 30;
        const year = day * 365;
        
        if (diff < minute) return 'baru saja';
        if (diff < hour) return `${Math.floor(diff / minute)} menit lalu`;
        if (diff < day) return `${Math.floor(diff / hour)} jam lalu`;
        if (diff < week) return `${Math.floor(diff / day)} hari lalu`;
        if (diff < month) return `${Math.floor(diff / week)} minggu lalu`;
        if (diff < year) return `${Math.floor(diff / month)} bulan lalu`;
        return `${Math.floor(diff / year)} tahun lalu`;
    },

    // Validasi email
    isValidEmail: (email) => {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    },

    // Validasi nomor WhatsApp Indonesia
    isValidWhatsApp: (phone) => {
        const re = /^628[1-9][0-9]{7,11}$/;
        return re.test(phone);
    },

    // Validasi password
    isValidPassword: (password) => {
        return password.length >= 8 && 
               /[A-Z]/.test(password) && 
               /[0-9]/.test(password) &&
               /[^A-Za-z0-9]/.test(password);
    },

    // Hash password sederhana (untuk demo, gunakan bcrypt di production)
    hashPassword: async (password) => {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    // Debounce function
    debounce: (func, wait) => {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    },

    // Throttle function
    throttle: (func, limit) => {
        let inThrottle;
        return function() {
            const args = arguments;
            const context = this;
            if (!inThrottle) {
                func.apply(context, args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    },

    // Local Storage dengan expiry
    setLocalStorage: (key, value, expiryHours = 24) => {
        const now = new Date();
        const item = {
            value: value,
            expiry: now.getTime() + (expiryHours * 60 * 60 * 1000)
        };
        localStorage.setItem(key, JSON.stringify(item));
    },

    getLocalStorage: (key) => {
        const itemStr = localStorage.getItem(key);
        if (!itemStr) return null;
        
        const item = JSON.parse(itemStr);
        const now = new Date();
        
        if (now.getTime() > item.expiry) {
            localStorage.removeItem(key);
            return null;
        }
        
        return item.value;
    },

    // Copy to clipboard
    copyToClipboard: async (text) => {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch (err) {
            console.error('Failed to copy: ', err);
            return false;
        }
    },

    // Generate random string
    generateId: (length = 8) => {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    },

    // Format bytes
    formatBytes: (bytes, decimals = 2) => {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    },

    // Parse CSV string
    parseCSV: (csvString) => {
        const lines = csvString.split('\n');
        const result = [];
        const headers = lines[0].split(',').map(h => h.trim());
        
        for (let i = 1; i < lines.length; i++) {
            if (!lines[i].trim()) continue;
            
            const obj = {};
            const currentline = lines[i].split(',');
            
            for (let j = 0; j < headers.length; j++) {
                obj[headers[j]] = currentline[j] ? currentline[j].trim() : '';
            }
            
            result.push(obj);
        }
        
        return result;
    },

    // Export data as CSV
    exportToCSV: (data, filename = 'export.csv') => {
        const csvContent = "data:text/csv;charset=utf-8," 
            + data.map(row => Object.values(row).join(",")).join("\n");
        
        const encodedUri = encodeURI(csvContent);
        const link = document.createElement("a");
        link.setAttribute("href", encodedUri);
        link.setAttribute("download", filename);
        document.body.appendChild(link);
        
        link.click();
        document.body.removeChild(link);
    },

    // Show notification
    showNotification: (title, message, type = 'info', duration = 5000) => {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-icon">
                <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            </div>
            <div class="notification-content">
                <strong>${title}</strong>
                <p>${message}</p>
            </div>
            <button class="notification-close">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        // Add to DOM
        const container = document.getElementById('notification-container') || createNotificationContainer();
        container.appendChild(notification);
        
        // Show with animation
        setTimeout(() => {
            notification.classList.add('show');
        }, 10);
        
        // Auto remove
        const removeTimeout = setTimeout(() => {
            removeNotification(notification);
        }, duration);
        
        // Close button
        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', () => {
            clearTimeout(removeTimeout);
            removeNotification(notification);
        });
        
        function createNotificationContainer() {
            const container = document.createElement('div');
            container.id = 'notification-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 9999;
                max-width: 400px;
            `;
            document.body.appendChild(container);
            return container;
        }
        
        function removeNotification(notification) {
            notification.classList.remove('show');
            setTimeout(() => {
                if (notification.parentElement) {
                    notification.parentElement.removeChild(notification);
                }
            }, 300);
        }
    },

    // Check internet connection
    checkConnection: async () => {
        try {
            const response = await fetch('https://www.google.com', { mode: 'no-cors' });
            return true;
        } catch (error) {
            return false;
        }
    },

    // Format phone number for display
    formatPhoneNumber: (phone) => {
        if (!phone) return '';
        const cleaned = phone.replace(/\D/g, '');
        
        if (cleaned.startsWith('62')) {
            return cleaned.replace(/(\d{2})(\d{3})(\d{4})(\d{1,4})/, '+$1 $2-$3-$4');
        } else if (cleaned.startsWith('0')) {
            return cleaned.replace(/(\d{1})(\d{3})(\d{4})(\d{1,4})/, '+62 $2-$3-$4');
        }
        
        return phone;
    },

    // Sanitize HTML
    sanitizeHTML: (str) => {
        const temp = document.createElement('div');
        temp.textContent = str;
        return temp.innerHTML;
    },

    // Get URL parameters
    getUrlParams: () => {
        const params = new URLSearchParams(window.location.search);
        const result = {};
        for (const [key, value] of params) {
            result[key] = value;
        }
        return result;
    },

    // Set URL parameter
    setUrlParam: (key, value) => {
        const url = new URL(window.location);
        url.searchParams.set(key, value);
        window.history.pushState({}, '', url);
    },

    // Remove URL parameter
    removeUrlParam: (key) => {
        const url = new URL(window.location);
        url.searchParams.delete(key);
        window.history.pushState({}, '', url);
    },

    // Download file
    downloadFile: (content, filename, contentType = 'text/plain') => {
        const blob = new Blob([content], { type: contentType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    },

    // Read file as text
    readFileAsText: (file) => {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
    },

    // Generate QR code data URL
    generateQRCode: async (text) => {
        try {
            const QRCode = await import('https://cdn.jsdelivr.net/npm/qrcode@1.5.3/build/qrcode.min.js');
            return await QRCode.toDataURL(text);
        } catch (error) {
            console.error('Failed to generate QR code:', error);
            return null;
        }
    },

    // Detect mobile device
    isMobile: () => {
        return /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
    },

    // Detect touch device
    isTouchDevice: () => {
        return 'ontouchstart' in window || navigator.maxTouchPoints > 0;
    },

    // Get browser info
    getBrowserInfo: () => {
        const ua = navigator.userAgent;
        let browser = 'Unknown';
        let version = 'Unknown';
        
        if (ua.includes('Firefox')) {
            browser = 'Firefox';
            version = ua.match(/Firefox\/(\d+)/)?.[1] || version;
        } else if (ua.includes('Chrome') && !ua.includes('Edg')) {
            browser = 'Chrome';
            version = ua.match(/Chrome\/(\d+)/)?.[1] || version;
        } else if (ua.includes('Safari') && !ua.includes('Chrome')) {
            browser = 'Safari';
            version = ua.match(/Version\/(\d+)/)?.[1] || version;
        } else if (ua.includes('Edg')) {
            browser = 'Edge';
            version = ua.match(/Edg\/(\d+)/)?.[1] || version;
        }
        
        return { browser, version };
    },

    // Get OS info
    getOSInfo: () => {
        const ua = navigator.userAgent;
        let os = 'Unknown';
        
        if (ua.includes('Windows')) os = 'Windows';
        else if (ua.includes('Mac')) os = 'macOS';
        else if (ua.includes('Linux')) os = 'Linux';
        else if (ua.includes('Android')) os = 'Android';
        else if (ua.includes('iOS') || ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
        
        return os;
    },

    // Check if element is in viewport
    isInViewport: (element) => {
        const rect = element.getBoundingClientRect();
        return (
            rect.top >= 0 &&
            rect.left >= 0 &&
            rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.right <= (window.innerWidth || document.documentElement.clientWidth)
        );
    },

    // Smooth scroll to element
    smoothScrollTo: (element, offset = 0) => {
        const elementPosition = element.getBoundingClientRect().top + window.pageYOffset;
        const offsetPosition = elementPosition - offset;
        
        window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
        });
    },

    // Format duration
    formatDuration: (seconds) => {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;
        
        const parts = [];
        if (hours > 0) parts.push(`${hours} jam`);
        if (minutes > 0) parts.push(`${minutes} menit`);
        if (secs > 0 || parts.length === 0) parts.push(`${secs} detik`);
        
        return parts.join(' ');
    },

    // Generate color from string
    stringToColor: (str) => {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            hash = str.charCodeAt(i) + ((hash << 5) - hash);
        }
        
        const hue = hash % 360;
        return `hsl(${hue}, 70%, 60%)`;
    },

    // Get initials from name
    getInitials: (name) => {
        return name
            .split(' ')
            .map(part => part[0])
            .join('')
            .toUpperCase()
            .substring(0, 2);
    },

    // Truncate text
    truncateText: (text, maxLength, suffix = '...') => {
        if (text.length <= maxLength) return text;
        return text.substring(0, maxLength - suffix.length) + suffix;
    },

    // Create data URL from image file
    createImageDataUrl: (file) => {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsDataURL(file);
        });
    },

    // Validate file size
    validateFileSize: (file, maxSizeMB) => {
        const maxSize = maxSizeMB * 1024 * 1024;
        return file.size <= maxSize;
    },

    // Validate file type
    validateFileType: (file, allowedTypes) => {
        return allowedTypes.includes(file.type);
    },

    // Create UUID
    createUUID: () => {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    },

    // Group array by key
    groupBy: (array, key) => {
        return array.reduce((result, item) => {
            (result[item[key]] = result[item[key]] || []).push(item);
            return result;
        }, {});
    },

    // Flatten object
    flattenObject: (obj, prefix = '') => {
        return Object.keys(obj).reduce((acc, k) => {
            const pre = prefix.length ? prefix + '.' : '';
            if (typeof obj[k] === 'object' && obj[k] !== null && !Array.isArray(obj[k])) {
                Object.assign(acc, Utils.flattenObject(obj[k], pre + k));
            } else {
                acc[pre + k] = obj[k];
            }
            return acc;
        }, {});
    },

    // Deep clone object
    deepClone: (obj) => {
        return JSON.parse(JSON.stringify(obj));
    },

    // Merge objects deeply
    deepMerge: (target, source) => {
        const output = Object.assign({}, target);
        if (Utils.isObject(target) && Utils.isObject(source)) {
            Object.keys(source).forEach(key => {
                if (Utils.isObject(source[key])) {
                    if (!(key in target))
                        Object.assign(output, { [key]: source[key] });
                    else
                        output[key] = Utils.deepMerge(target[key], source[key]);
                } else {
                    Object.assign(output, { [key]: source[key] });
                }
            });
        }
        return output;
    },

    // Check if value is object
    isObject: (item) => {
        return (item && typeof item === 'object' && !Array.isArray(item));
    },

    // Remove duplicates from array
    removeDuplicates: (array, key) => {
        const seen = new Set();
        return array.filter(item => {
            const value = key ? item[key] : item;
            if (seen.has(value)) {
                return false;
            }
            seen.add(value);
            return true;
        });
    },

    // Sort array by key
    sortBy: (array, key, order = 'asc') => {
        return array.sort((a, b) => {
            const valueA = key ? a[key] : a;
            const valueB = key ? b[key] : b;
            
            if (valueA < valueB) return order === 'asc' ? -1 : 1;
            if (valueA > valueB) return order === 'asc' ? 1 : -1;
            return 0;
        });
    },

    // Calculate percentage
    calculatePercentage: (value, total) => {
        if (total === 0) return 0;
        return Math.round((value / total) * 100);
    },

    // Generate random number in range
    randomInRange: (min, max) => {
        return Math.floor(Math.random() * (max - min + 1)) + min;
    },

    // Get current timestamp
    getTimestamp: () => {
        return Date.now();
    },

    // Format timestamp
    formatTimestamp: (timestamp) => {
        return new Date(timestamp).toISOString();
    },

    // Parse query string
    parseQueryString: (queryString) => {
        return Object.fromEntries(new URLSearchParams(queryString));
    },

    // Stringify object to query string
    stringifyQuery: (obj) => {
        return new URLSearchParams(obj).toString();
    },

    // Create element with attributes
    createElement: (tag, attributes = {}, children = []) => {
        const element = document.createElement(tag);
        
        // Set attributes
        Object.entries(attributes).forEach(([key, value]) => {
            if (key === 'className') {
                element.className = value;
            } else if (key === 'textContent') {
                element.textContent = value;
            } else if (key === 'innerHTML') {
                element.innerHTML = value;
            } else {
                element.setAttribute(key, value);
            }
        });
        
        // Add children
        children.forEach(child => {
            if (typeof child === 'string') {
                element.appendChild(document.createTextNode(child));
            } else {
                element.appendChild(child);
            }
        });
        
        return element;
    },

    // Remove element
    removeElement: (element) => {
        if (element && element.parentNode) {
            element.parentNode.removeChild(element);
        }
    },

    // Toggle element visibility
    toggleElement: (element, show) => {
        if (show === undefined) {
            element.style.display = element.style.display === 'none' ? '' : 'none';
        } else {
            element.style.display = show ? '' : 'none';
        }
    },

    // Add event listener with options
    on: (element, event, handler, options = {}) => {
        element.addEventListener(event, handler, options);
        return () => element.removeEventListener(event, handler, options);
    },

    // Remove event listener
    off: (element, event, handler, options = {}) => {
        element.removeEventListener(event, handler, options);
    },

    // Trigger custom event
    triggerEvent: (element, eventName, detail = {}) => {
        const event = new CustomEvent(eventName, { detail });
        element.dispatchEvent(event);
    },

    // Get computed style
    getStyle: (element, property) => {
        return window.getComputedStyle(element).getPropertyValue(property);
    },

    // Set multiple styles
    setStyles: (element, styles) => {
        Object.assign(element.style, styles);
    },

    // Add class with vendor prefix
    addClass: (element, className) => {
        element.classList.add(className);
    },

    // Remove class
    removeClass: (element, className) => {
        element.classList.remove(className);
    },

    // Toggle class
    toggleClass: (element, className, force) => {
        if (force === undefined) {
            element.classList.toggle(className);
        } else {
            element.classList.toggle(className, force);
        }
    },

    // Check if element has class
    hasClass: (element, className) => {
        return element.classList.contains(className);
    },

    // Get siblings
    getSiblings: (element) => {
        return Array.from(element.parentNode.children).filter(child => child !== element);
    },

    // Get next sibling
    getNextSibling: (element) => {
        return element.nextElementSibling;
    },

    // Get previous sibling
    getPreviousSibling: (element) => {
        return element.previousElementSibling;
    },

    // Get parent by selector
    getParentBySelector: (element, selector) => {
        let parent = element.parentElement;
        while (parent) {
            if (parent.matches(selector)) return parent;
            parent = parent.parentElement;
        }
        return null;
    },

    // Find elements by selector within context
    findAll: (selector, context = document) => {
        return Array.from(context.querySelectorAll(selector));
    },

    // Find element by selector within context
    find: (selector, context = document) => {
        return context.querySelector(selector);
    },

    // Get form data as object
    getFormData: (form) => {
        const formData = new FormData(form);
        const data = {};
        formData.forEach((value, key) => {
            if (data[key]) {
                if (!Array.isArray(data[key])) {
                    data[key] = [data[key]];
                }
                data[key].push(value);
            } else {
                data[key] = value;
            }
        });
        return data;
    },

    // Set form data from object
    setFormData: (form, data) => {
        Object.entries(data).forEach(([key, value]) => {
            const element = form.querySelector(`[name="${key}"]`);
            if (element) {
                if (element.type === 'checkbox' || element.type === 'radio') {
                    if (Array.isArray(value)) {
                        element.checked = value.includes(element.value);
                    } else {
                        element.checked = element.value === value;
                    }
                } else if (element.type === 'select-multiple') {
                    Array.from(element.options).forEach(option => {
                        option.selected = value.includes(option.value);
                    });
                } else {
                    element.value = value;
                }
            }
        });
    },

    // Reset form
    resetForm: (form) => {
        form.reset();
    },

    // Validate form
    validateForm: (form) => {
        const elements = form.elements;
        let isValid = true;
        const errors = [];
        
        for (let i = 0; i < elements.length; i++) {
            const element = elements[i];
            if (element.required && !element.value.trim()) {
                isValid = false;
                errors.push({
                    element,
                    message: `${element.name || element.id} harus diisi`
                });
            }
            
            if (element.type === 'email' && element.value) {
                if (!Utils.isValidEmail(element.value)) {
                    isValid = false;
                    errors.push({
                        element,
                        message: 'Format email tidak valid'
                    });
                }
            }
        }
        
        return { isValid, errors };
    },

    // Create modal
    createModal: (options = {}) => {
        const {
            title = 'Modal',
            content = '',
            buttons = [],
            size = 'md',
            onClose = () => {}
        } = options;
        
        // Create modal element
        const modal = Utils.createElement('div', {
            className: 'modal',
            style: `
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                align-items: center;
                justify-content: center;
                z-index: 10000;
                opacity: 0;
                transition: opacity 0.3s;
            `
        });
        
        const modalContent = Utils.createElement('div', {
            className: 'modal-content',
            style: `
                background: white;
                border-radius: 12px;
                padding: 30px;
                max-width: ${size === 'sm' ? '400px' : size === 'lg' ? '800px' : '600px'};
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
                transform: translateY(-20px);
                transition: transform 0.3s;
            `
        });
        
        const modalHeader = Utils.createElement('div', {
            className: 'modal-header',
            style: `
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            `
        });
        
        const modalTitle = Utils.createElement('h3', {
            className: 'modal-title',
            textContent: title,
            style: `
                margin: 0;
                color: #1e293b;
            `
        });
        
        const closeButton = Utils.createElement('button', {
            className: 'modal-close',
            innerHTML: '&times;',
            style: `
                background: none;
                border: none;
                font-size: 24px;
                cursor: pointer;
                color: #64748b;
                padding: 0;
                width: 30px;
                height: 30px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
            `
        });
        
        const modalBody = Utils.createElement('div', {
            className: 'modal-body',
            innerHTML: content,
            style: `
                margin-bottom: 30px;
            `
        });
        
        const modalFooter = Utils.createElement('div', {
            className: 'modal-footer',
            style: `
                display: flex;
                justify-content: flex-end;
                gap: 10px;
            `
        });
        
        // Add buttons
        buttons.forEach(button => {
            const btn = Utils.createElement('button', {
                className: `btn btn-${button.type || 'secondary'}`,
                textContent: button.text,
                style: button.style
            });
            
            btn.addEventListener('click', () => {
                if (button.onClick) button.onClick();
                if (button.close !== false) closeModal();
            });
            
            modalFooter.appendChild(btn);
        });
        
        // Add close functionality
        const closeModal = () => {
            modal.style.opacity = '0';
            modalContent.style.transform = 'translateY(-20px)';
            setTimeout(() => {
                document.body.removeChild(modal);
                onClose();
            }, 300);
        };
        
        closeButton.addEventListener('click', closeModal);
        
        modal.addEventListener('click', (e) => {
            if (e.target === modal) closeModal();
        });
        
        // Assemble modal
        modalHeader.appendChild(modalTitle);
        modalHeader.appendChild(closeButton);
        
        modalContent.appendChild(modalHeader);
        modalContent.appendChild(modalBody);
        modalContent.appendChild(modalFooter);
        
        modal.appendChild(modalContent);
        document.body.appendChild(modal);
        
        // Show modal
        setTimeout(() => {
            modal.style.opacity = '1';
            modalContent.style.transform = 'translateY(0)';
        }, 10);
        
        // Return modal instance
        return {
            element: modal,
            close: closeModal,
            updateContent: (newContent) => {
                modalBody.innerHTML = newContent;
            }
        };
    },

    // Create confirmation dialog
    confirm: async (options = {}) => {
        return new Promise((resolve) => {
            const {
                title = 'Konfirmasi',
                message = 'Apakah Anda yakin?',
                confirmText = 'Ya',
                cancelText = 'Tidak',
                type = 'warning'
            } = options;
            
            const modal = Utils.createModal({
                title,
                content: `
                    <div style="text-align: center; padding: 20px 0;">
                        <div style="font-size: 48px; color: ${type === 'warning' ? '#f59e0b' : type === 'danger' ? '#ef4444' : '#3b82f6'}; margin-bottom: 20px;">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <p style="color: #64748b; font-size: 16px; line-height: 1.6;">${message}</p>
                    </div>
                `,
                buttons: [
                    {
                        text: cancelText,
                        type: 'secondary',
                        onClick: () => resolve(false)
                    },
                    {
                        text: confirmText,
                        type: type === 'danger' ? 'danger' : 'primary',
                        onClick: () => resolve(true)
                    }
                ],
                size: 'sm',
                onClose: () => resolve(false)
            });
        });
    },

    // Create alert dialog
    alert: async (options = {}) => {
        return new Promise((resolve) => {
            const {
                title = 'Informasi',
                message = '',
                type = 'info',
                buttonText = 'OK'
            } = options;
            
            const icons = {
                info: 'info-circle',
                success: 'check-circle',
                warning: 'exclamation-triangle',
                error: 'exclamation-circle'
            };
            
            const colors = {
                info: '#3b82f6',
                success: '#10b981',
                warning: '#f59e0b',
                error: '#ef4444'
            };
            
            const modal = Utils.createModal({
                title,
                content: `
                    <div style="text-align: center; padding: 20px 0;">
                        <div style="font-size: 48px; color: ${colors[type]}; margin-bottom: 20px;">
                            <i class="fas fa-${icons[type]}"></i>
                        </div>
                        <p style="color: #64748b; font-size: 16px; line-height: 1.6;">${message}</p>
                    </div>
                `,
                buttons: [
                    {
                        text: buttonText,
                        type: 'primary',
                        onClick: () => resolve()
                    }
                ],
                size: 'sm',
                onClose: () => resolve()
            });
        });
    },

    // Create loading spinner
    createLoader: (options = {}) => {
        const {
            size = 'md',
            color = '#667eea',
            text = '',
            overlay = false
        } = options;
        
        const sizes = {
            sm: '24px',
            md: '40px',
            lg: '60px'
        };
        
        const loader = Utils.createElement('div', {
            className: 'loader',
            style: `
                display: inline-flex;
                flex-direction: column;
                align-items: center;
                gap: 12px;
            `
        });
        
        const spinner = Utils.createElement('div', {
            className: 'loader-spinner',
            style: `
                width: ${sizes[size]};
                height: ${sizes[size]};
                border: 3px solid rgba(0, 0, 0, 0.1);
                border-radius: 50%;
                border-top-color: ${color};
                animation: spin 1s linear infinite;
            `
        });
        
        loader.appendChild(spinner);
        
        if (text) {
            const textElement = Utils.createElement('div', {
                className: 'loader-text',
                textContent: text,
                style: `
                    color: #64748b;
                    font-size: 14px;
                `
            });
            loader.appendChild(textElement);
        }
        
        if (overlay) {
            const overlayElement = Utils.createElement('div', {
                className: 'loader-overlay',
                style: `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(255, 255, 255, 0.8);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    z-index: 9999;
                `
            });
            overlayElement.appendChild(loader);
            return overlayElement;
        }
        
        return loader;
    },

    // Show loading
    showLoading: (options = {}) => {
        const loader = Utils.createLoader({ ...options, overlay: true });
        loader.id = 'global-loader';
        document.body.appendChild(loader);
        return loader;
    },

    // Hide loading
    hideLoading: () => {
        const loader = document.getElementById('global-loader');
        if (loader) {
            loader.remove();
        }
    },

    // Create toast
    createToast: (options = {}) => {
        const {
            title = '',
            message = '',
            type = 'info',
            duration = 5000,
            position = 'top-right'
        } = options;
        
        const icons = {
            info: 'info-circle',
            success: 'check-circle',
            warning: 'exclamation-triangle',
            error: 'exclamation-circle'
        };
        
        const colors = {
            info: '#3b82f6',
            success: '#10b981',
            warning: '#f59e0b',
            error: '#ef4444'
        };
        
        const toast = Utils.createElement('div', {
            className: 'toast',
            style: `
                background: white;
                border-radius: 8px;
                padding: 16px;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                min-width: 300px;
                max-width: 400px;
                margin-bottom: 10px;
                border-left: 4px solid ${colors[type]};
                transform: translateX(400px);
                opacity: 0;
                transition: all 0.3s;
            `
        });
        
        const toastContent = Utils.createElement('div', {
            className: 'toast-content',
            style: `
                display: flex;
                align-items: flex-start;
                gap: 12px;
            `
        });
        
        const toastIcon = Utils.createElement('div', {
            className: 'toast-icon',
            style: `
                color: ${colors[type]};
                font-size: 20px;
                flex-shrink: 0;
            `
        });
        
        toastIcon.innerHTML = `<i class="fas fa-${icons[type]}"></i>`;
        
        const toastText = Utils.createElement('div', {
            className: 'toast-text',
            style: `
                flex: 1;
            `
        });
        
        if (title) {
            const toastTitle = Utils.createElement('div', {
                className: 'toast-title',
                textContent: title,
                style: `
                    font-weight: 600;
                    color: #1e293b;
                    margin-bottom: 4px;
                `
            });
            toastText.appendChild(toastTitle);
        }
        
        const toastMessage = Utils.createElement('div', {
            className: 'toast-message',
            textContent: message,
            style: `
                color: #64748b;
                font-size: 14px;
                line-height: 1.4;
            `
        });
        toastText.appendChild(toastMessage);
        
        const toastClose = Utils.createElement('button', {
            className: 'toast-close',
            innerHTML: '&times;',
            style: `
                background: none;
                border: none;
                font-size: 20px;
                cursor: pointer;
                color: #94a3b8;
                padding: 0;
                width: 24px;
                height: 24px;
                display: flex;
                align-items: center;
                justify-content: center;
                flex-shrink: 0;
            `
        });
        
        toastContent.appendChild(toastIcon);
        toastContent.appendChild(toastText);
        toastContent.appendChild(toastClose);
        toast.appendChild(toastContent);
        
        // Get or create container
        const containerId = `toast-container-${position}`;
        let container = document.getElementById(containerId);
        
        if (!container) {
            container = Utils.createElement('div', {
                id: containerId,
                style: `
                    position: fixed;
                    ${position.includes('top') ? 'top' : 'bottom'}: 20px;
                    ${position.includes('left') ? 'left' : 'right'}: 20px;
                    z-index: 9999;
                    display: flex;
                    flex-direction: ${position.includes('top') ? 'column' : 'column-reverse'};
                `
            });
            document.body.appendChild(container);
        }
        
        container.appendChild(toast);
        
        // Show toast
        setTimeout(() => {
            toast.style.transform = 'translateX(0)';
            toast.style.opacity = '1';
        }, 10);
        
        // Auto remove
        const removeTimeout = setTimeout(() => {
            removeToast();
        }, duration);
        
        // Close button
        const removeToast = () => {
            toast.style.transform = 'translateX(400px)';
            toast.style.opacity = '0';
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.parentElement.removeChild(toast);
                }
            }, 300);
        };
        
        toastClose.addEventListener('click', () => {
            clearTimeout(removeTimeout);
            removeToast();
        });
        
        return toast;
    },

    // Show success toast
    showSuccess: (message, title = 'Berhasil!', options = {}) => {
        return Utils.createToast({
            title,
            message,
            type: 'success',
            ...options
        });
    },

    // Show error toast
    showError: (message, title = 'Error!', options = {}) => {
        return Utils.createToast({
            title,
            message,
            type: 'error',
            ...options
        });
    },

    // Show warning toast
    showWarning: (message, title = 'Peringatan!', options = {}) => {
        return Utils.createToast({
            title,
            message,
            type: 'warning',
            ...options
        });
    },

    // Show info toast
    showInfo: (message, title = 'Informasi', options = {}) => {
        return Utils.createToast({
            title,
            message,
            type: 'info',
            ...options
        });
    },

    // Create pagination
    createPagination: (options = {}) => {
        const {
            currentPage = 1,
            totalPages = 1,
            onPageChange = () => {},
            maxVisible = 5
        } = options;
        
        const pagination = Utils.createElement('nav', {
            className: 'pagination',
            style: `
                display: flex;
                align-items: center;
                gap: 8px;
            `
        });
        
        // Previous button
        const prevButton = Utils.createElement('button', {
            className: 'pagination-button pagination-prev',
            innerHTML: '<i class="fas fa-chevron-left"></i>',
            disabled: currentPage === 1,
            style: `
                padding: 8px 12px;
                border: 1px solid #e2e8f0;
                background: ${currentPage === 1 ? '#f8fafc' : 'white'};
                color: ${currentPage === 1 ? '#cbd5e1' : '#64748b'};
                border-radius: 6px;
                cursor: ${currentPage === 1 ? 'not-allowed' : 'pointer'};
                transition: all 0.2s;
            `
        });
        
        if (currentPage > 1) {
            prevButton.addEventListener('click', () => onPageChange(currentPage - 1));
        }
        
        pagination.appendChild(prevButton);
        
        // Page numbers
        const startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
        const endPage = Math.min(totalPages, startPage + maxVisible - 1);
        
        for (let i = startPage; i <= endPage; i++) {
            const pageButton = Utils.createElement('button', {
                className: 'pagination-button pagination-page',
                textContent: i.toString(),
                'data-page': i,
                style: `
                    padding: 8px 12px;
                    border: 1px solid #e2e8f0;
                    background: ${i === currentPage ? '#667eea' : 'white'};
                    color: ${i === currentPage ? 'white' : '#64748b'};
                    border-radius: 6px;
                    cursor: pointer;
                    transition: all 0.2s;
                    min-width: 40px;
                `
            });
            
            if (i !== currentPage) {
                pageButton.addEventListener('click', () => onPageChange(i));
            }
            
            pagination.appendChild(pageButton);
        }
        
        // Next button
        const nextButton = Utils.createElement('button', {
            className: 'pagination-button pagination-next',
            innerHTML: '<i class="fas fa-chevron-right"></i>',
            disabled: currentPage === totalPages,
            style: `
                padding: 8px 12px;
                border: 1px solid #e2e8f0;
                background: ${currentPage === totalPages ? '#f8fafc' : 'white'};
                color: ${currentPage === totalPages ? '#cbd5e1' : '#64748b'};
                border-radius: 6px;
                cursor: ${currentPage === totalPages ? 'not-allowed' : 'pointer'};
                transition: all 0.2s;
            `
        });
        
        if (currentPage < totalPages) {
            nextButton.addEventListener('click', () => onPageChange(currentPage + 1));
        }
        
        pagination.appendChild(nextButton);
        
        // Page info
        const pageInfo = Utils.createElement('div', {
            className: 'pagination-info',
            textContent: `Halaman ${currentPage} dari ${totalPages}`,
            style: `
                margin-left: 16px;
                color: #64748b;
                font-size: 14px;
            `
        });
        
        pagination.appendChild(pageInfo);
        
        return pagination;
    },

    // Create dropdown
    createDropdown: (options = {}) => {
        const {
            items = [],
            placeholder = 'Pilih opsi',
            onSelect = () => {},
            value = ''
        } = options;
        
        const dropdown = Utils.createElement('div', {
            className: 'dropdown',
            style: `
                position: relative;
                display: inline-block;
            `
        });
        
        const dropdownButton = Utils.createElement('button', {
            className: 'dropdown-button',
            style: `
                padding: 10px 16px;
                border: 2px solid #e2e8f0;
                background: white;
                color: #1e293b;
                border-radius: 8px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 8px;
                min-width: 200px;
                transition: all 0.2s;
            `
        });
        
        const buttonText = Utils.createElement('span', {
            className: 'dropdown-button-text',
            textContent: placeholder
        });
        
        const buttonIcon = Utils.createElement('span', {
            className: 'dropdown-button-icon',
            innerHTML: '<i class="fas fa-chevron-down"></i>',
            style: `
                transition: transform 0.2s;
            `
        });
        
        dropdownButton.appendChild(buttonText);
        dropdownButton.appendChild(buttonIcon);
        
        const dropdownMenu = Utils.createElement('div', {
            className: 'dropdown-menu',
            style: `
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                background: white;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                margin-top: 4px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                z-index: 1000;
                max-height: 300px;
                overflow-y: auto;
                display: none;
            `
        });
        
        items.forEach(item => {
            const dropdownItem = Utils.createElement('div', {
                className: 'dropdown-item',
                'data-value': item.value,
                textContent: item.label,
                style: `
                    padding: 10px 16px;
                    cursor: pointer;
                    transition: background 0.2s;
                `
            });
            
            if (item.value === value) {
                dropdownItem.style.background = '#f1f5f9';
                buttonText.textContent = item.label;
            }
            
            dropdownItem.addEventListener('click', () => {
                buttonText.textContent = item.label;
                onSelect(item.value);
                toggleDropdown();
            });
            
            dropdownItem.addEventListener('mouseenter', () => {
                dropdownItem.style.background = '#f8fafc';
            });
            
            dropdownItem.addEventListener('mouseleave', () => {
                dropdownItem.style.background = item.value === value ? '#f1f5f9' : 'white';
            });
            
            dropdownMenu.appendChild(dropdownItem);
        });
        
        const toggleDropdown = () => {
            const isOpen = dropdownMenu.style.display === 'block';
            dropdownMenu.style.display = isOpen ? 'none' : 'block';
            buttonIcon.style.transform = isOpen ? 'rotate(0deg)' : 'rotate(180deg)';
        };
        
        dropdownButton.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleDropdown();
        });
        
        document.addEventListener('click', () => {
            dropdownMenu.style.display = 'none';
            buttonIcon.style.transform = 'rotate(0deg)';
        });
        
        dropdown.appendChild(dropdownButton);
        dropdown.appendChild(dropdownMenu);
        
        return dropdown;
    },

    // Create tabs
    createTabs: (options = {}) => {
        const {
            tabs = [],
            activeTab = 0,
            onTabChange = () => {}
        } = options;
        
        const tabsContainer = Utils.createElement('div', {
            className: 'tabs-container',
            style: `
                display: flex;
                flex-direction: column;
            `
        });
        
        const tabsHeader = Utils.createElement('div', {
            className: 'tabs-header',
            style: `
                display: flex;
                border-bottom: 2px solid #e2e8f0;
                gap: 4px;
            `
        });
        
        const tabsContent = Utils.createElement('div', {
            className: 'tabs-content',
            style: `
                padding: 20px 0;
            `
        });
        
        tabs.forEach((tab, index) => {
            const tabButton = Utils.createElement('button', {
                className: 'tab-button',
                'data-tab': index,
                textContent: tab.label,
                style: `
                    padding: 12px 24px;
                    border: none;
                    background: none;
                    cursor: pointer;
                    font-weight: 600;
                    color: #64748b;
                    border-bottom: 3px solid transparent;
                    margin-bottom: -2px;
                    transition: all 0.2s;
                `
            });
            
            if (index === activeTab) {
                tabButton.style.color = '#667eea';
                tabButton.style.borderBottomColor = '#667eea';
            }
            
            tabButton.addEventListener('click', () => {
                // Update active tab
                tabsHeader.querySelectorAll('.tab-button').forEach((btn, i) => {
                    btn.style.color = i === index ? '#667eea' : '#64748b';
                    btn.style.borderBottomColor = i === index ? '#667eea' : 'transparent';
                });
                
                // Update content
                tabsContent.innerHTML = tab.content;
                
                // Call callback
                onTabChange(index);
            });
            
            tabsHeader.appendChild(tabButton);
        });
        
        // Set initial content
        if (tabs[activeTab]) {
            tabsContent.innerHTML = tabs[activeTab].content;
        }
        
        tabsContainer.appendChild(tabsHeader);
        tabsContainer.appendChild(tabsContent);
        
        return tabsContainer;
    },

    // Create accordion
    createAccordion: (options = {}) => {
        const {
            items = [],
            multiple = false
        } = options;
        
        const accordion = Utils.createElement('div', {
            className: 'accordion',
            style: `
                display: flex;
                flex-direction: column;
                gap: 8px;
            `
        });
        
        items.forEach((item, index) => {
            const accordionItem = Utils.createElement('div', {
                className: 'accordion-item',
                style: `
                    border: 2px solid #e2e8f0;
                    border-radius: 8px;
                    overflow: hidden;
                `
            });
            
            const accordionHeader = Utils.createElement('div', {
                className: 'accordion-header',
                style: `
                    padding: 16px;
                    background: #f8fafc;
                    cursor: pointer;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    transition: background 0.2s;
                `
            });
            
            const headerTitle = Utils.createElement('div', {
                className: 'accordion-title',
                textContent: item.title,
                style: `
                    font-weight: 600;
                    color: #1e293b;
                `
            });
            
            const headerIcon = Utils.createElement('div', {
                className: 'accordion-icon',
                innerHTML: '<i class="fas fa-chevron-down"></i>',
                style: `
                    transition: transform 0.2s;
                `
            });
            
            accordionHeader.appendChild(headerTitle);
            accordionHeader.appendChild(headerIcon);
            
            const accordionContent = Utils.createElement('div', {
                className: 'accordion-content',
                innerHTML: item.content,
                style: `
                    padding: 0 16px;
                    max-height: 0;
                    overflow: hidden;
                    transition: all 0.3s;
                `
            });
            
            const toggleAccordion = () => {
                const isOpen = accordionContent.style.maxHeight !== '0px';
                
                if (!multiple && !isOpen) {
                    // Close other items
                    accordion.querySelectorAll('.accordion-content').forEach(content => {
                        content.style.maxHeight = '0';
                        content.style.padding = '0 16px';
                    });
                    
                    accordion.querySelectorAll('.accordion-icon').forEach(icon => {
                        icon.style.transform = 'rotate(0deg)';
                    });
                    
                    accordion.querySelectorAll('.accordion-header').forEach(header => {
                        header.style.background = '#f8fafc';
                    });
                }
                
                if (isOpen) {
                    accordionContent.style.maxHeight = '0';
                    accordionContent.style.padding = '0 16px';
                    headerIcon.style.transform = 'rotate(0deg)';
                    accordionHeader.style.background = '#f8fafc';
                } else {
                    accordionContent.style.maxHeight = accordionContent.scrollHeight + 'px';
                    accordionContent.style.padding = '16px';
                    headerIcon.style.transform = 'rotate(180deg)';
                    accordionHeader.style.background = '#f1f5f9';
                }
            };
            
            accordionHeader.addEventListener('click', toggleAccordion);
            
            // Open first item by default
            if (index === 0) {
                toggleAccordion();
            }
            
            accordionItem.appendChild(accordionHeader);
            accordionItem.appendChild(accordionContent);
            accordion.appendChild(accordionItem);
        });
        
        return accordion;
    },

    // Create tooltip
    createTooltip: (element, options = {}) => {
        const {
            content = '',
            position = 'top',
            delay = 200
        } = options;
        
        const tooltip = Utils.createElement('div', {
            className: 'tooltip',
            textContent: content,
            style: `
                position: absolute;
                background: #1e293b;
                color: white;
                padding: 6px 12px;
                border-radius: 4px;
                font-size: 12px;
                white-space: nowrap;
                z-index: 1000;
                opacity: 0;
                transition: opacity 0.2s;
                pointer-events: none;
            `
        });
        
        let timeout;
        
        const showTooltip = () => {
            timeout = setTimeout(() => {
                document.body.appendChild(tooltip);
                
                const rect = element.getBoundingClientRect();
                const tooltipRect = tooltip.getBoundingClientRect();
                
                let top, left;
                
                switch (position) {
                    case 'top':
                        top = rect.top - tooltipRect.height - 8;
                        left = rect.left + (rect.width - tooltipRect.width) / 2;
                        break;
                    case 'bottom':
                        top = rect.bottom + 8;
                        left = rect.left + (rect.width - tooltipRect.width) / 2;
                        break;
                    case 'left':
                        top = rect.top + (rect.height - tooltipRect.height) / 2;
                        left = rect.left - tooltipRect.width - 8;
                        break;
                    case 'right':
                        top = rect.top + (rect.height - tooltipRect.height) / 2;
                        left = rect.right + 8;
                        break;
                }
                
                tooltip.style.top = Math.max(8, top) + 'px';
                tooltip.style.left = Math.max(8, left) + 'px';
                tooltip.style.opacity = '1';
            }, delay);
        };
        
        const hideTooltip = () => {
            clearTimeout(timeout);
            if (tooltip.parentElement) {
                tooltip.style.opacity = '0';
                setTimeout(() => {
                    if (tooltip.parentElement) {
                        tooltip.parentElement.removeChild(tooltip);
                    }
                }, 200);
            }
        };
        
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
        element.addEventListener('focus', showTooltip);
        element.addEventListener('blur', hideTooltip);
        
        return {
            element: tooltip,
            update: (newContent) => {
                tooltip.textContent = newContent;
            },
            destroy: () => {
                hideTooltip();
                element.removeEventListener('mouseenter', showTooltip);
                element.removeEventListener('mouseleave', hideTooltip);
                element.removeEventListener('focus', showTooltip);
                element.removeEventListener('blur', hideTooltip);
            }
        };
    },

    // Create chart (using Chart.js if available)
    createChart: (canvas, options = {}) => {
        if (typeof Chart === 'undefined') {
            console.warn('Chart.js is not loaded. Please include Chart.js library.');
            return null;
        }
        
        const {
            type = 'line',
            data = {},
            config = {}
        } = options;
        
        return new Chart(canvas, {
            type,
            data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    tooltip: {
                        mode: 'index',
                        intersect: false,
                    }
                },
                ...config
            }
        });
    },

    // Create calendar
    createCalendar: (options = {}) => {
        const {
            date = new Date(),
            onDateSelect = () => {},
            minDate = null,
            maxDate = null
        } = options;
        
        const calendar = Utils.createElement('div', {
            className: 'calendar',
            style: `
                background: white;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                padding: 16px;
                min-width: 300px;
            `
        });
        
        const currentDate = new Date(date);
        
        const header = Utils.createElement('div', {
            className: 'calendar-header',
            style: `
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 16px;
            `
        });
        
        const prevButton = Utils.createElement('button', {
            className: 'calendar-nav calendar-prev',
            innerHTML: '<i class="fas fa-chevron-left"></i>',
            style: `
                background: none;
                border: none;
                cursor: pointer;
                padding: 8px;
                color: #64748b;
                border-radius: 4px;
                transition: background 0.2s;
            `
        });
        
        const nextButton = Utils.createElement('button', {
            className: 'calendar-nav calendar-next',
            innerHTML: '<i class="fas fa-chevron-right"></i>',
            style: `
                background: none;
                border: none;
                cursor: pointer;
                padding: 8px;
                color: #64748b;
                border-radius: 4px;
                transition: background 0.2s;
            `
        });
        
        const monthYear = Utils.createElement('div', {
            className: 'calendar-month-year',
            textContent: currentDate.toLocaleDateString('id-ID', { month: 'long', year: 'numeric' }),
            style: `
                font-weight: 600;
                color: #1e293b;
            `
        });
        
        header.appendChild(prevButton);
        header.appendChild(monthYear);
        header.appendChild(nextButton);
        
        const weekdays = ['M', 'S', 'S', 'R', 'K', 'J', 'S'];
        const weekdaysRow = Utils.createElement('div', {
            className: 'calendar-weekdays',
            style: `
                display: grid;
                grid-template-columns: repeat(7, 1fr);
                gap: 4px;
                margin-bottom: 8px;
            `
        });
        
        weekdays.forEach(day => {
            const dayElement = Utils.createElement('div', {
                className: 'calendar-weekday',
                textContent: day,
                style: `
                    text-align: center;
                    font-weight: 600;
                    color: #64748b;
                    padding: 8px;
                `
            });
            weekdaysRow.appendChild(dayElement);
        });
        
        const daysGrid = Utils.createElement('div', {
            className: 'calendar-days',
            style: `
                display: grid;
                grid-template-columns: repeat(7, 1fr);
                gap: 4px;
            `
        });
        
        const updateCalendar = () => {
            daysGrid.innerHTML = '';
            
            const year = currentDate.getFullYear();
            const month = currentDate.getMonth();
            
            const firstDay = new Date(year, month, 1);
            const lastDay = new Date(year, month + 1, 0);
            
            const firstDayIndex = (firstDay.getDay() + 6) % 7;
            const daysInMonth = lastDay.getDate();
            
            // Previous month days
            const prevMonthLastDay = new Date(year, month, 0).getDate();
            for (let i = 0; i < firstDayIndex; i++) {
                const day = prevMonthLastDay - firstDayIndex + i + 1;
                const dayElement = Utils.createElement('div', {
                    className: 'calendar-day calendar-day-prev',
                    textContent: day.toString(),
                    style: `
                        text-align: center;
                        padding: 8px;
                        color: #cbd5e1;
                        border-radius: 4px;
                    `
                });
                daysGrid.appendChild(dayElement);
            }
            
            // Current month days
            const today = new Date();
            for (let day = 1; day <= daysInMonth; day++) {
                const date = new Date(year, month, day);
                const isToday = date.toDateString() === today.toDateString();
                const isSelected = date.toDateString() === new Date(date).toDateString();
                const isDisabled = (minDate && date < minDate) || (maxDate && date > maxDate);
                
                const dayElement = Utils.createElement('button', {
                    className: 'calendar-day',
                    textContent: day.toString(),
                    disabled: isDisabled,
                    style: `
                        text-align: center;
                        padding: 8px;
                        background: ${isToday ? '#f1f5f9' : 'white'};
                        color: ${isDisabled ? '#cbd5e1' : isSelected ? 'white' : '#1e293b'};
                        border: 2px solid ${isSelected ? '#667eea' : 'transparent'};
                        border-radius: 4px;
                        cursor: ${isDisabled ? 'not-allowed' : 'pointer'};
                        transition: all 0.2s;
                    `
                });
                
                if (isSelected) {
                    dayElement.style.background = '#667eea';
                }
                
                if (!isDisabled) {
                    dayElement.addEventListener('click', () => {
                        onDateSelect(date);
                    });
                    
                    dayElement.addEventListener('mouseenter', () => {
                        if (!isSelected) {
                            dayElement.style.background = '#f1f5f9';
                        }
                    });
                    
                    dayElement.addEventListener('mouseleave', () => {
                        if (!isSelected) {
                            dayElement.style.background = isToday ? '#f1f5f9' : 'white';
                        }
                    });
                }
                
                daysGrid.appendChild(dayElement);
            }
            
            // Next month days
            const nextMonthDays = 42 - (firstDayIndex + daysInMonth);
            for (let i = 1; i <= nextMonthDays; i++) {
                const dayElement = Utils.createElement('div', {
                    className: 'calendar-day calendar-day-next',
                    textContent: i.toString(),
                    style: `
                        text-align: center;
                        padding: 8px;
                        color: #cbd5e1;
                        border-radius: 4px;
                    `
                });
                daysGrid.appendChild(dayElement);
            }
        };
        
        prevButton.addEventListener('click', () => {
            currentDate.setMonth(currentDate.getMonth() - 1);
            monthYear.textContent = currentDate.toLocaleDateString('id-ID', { month: 'long', year: 'numeric' });
            updateCalendar();
        });
        
        nextButton.addEventListener('click', () => {
            currentDate.setMonth(currentDate.getMonth() + 1);
            monthYear.textContent = currentDate.toLocaleDateString('id-ID', { month: 'long', year: 'numeric' });
            updateCalendar();
        });
        
        calendar.appendChild(header);
        calendar.appendChild(weekdaysRow);
        calendar.appendChild(daysGrid);
        
        updateCalendar();
        
        return calendar;
    },

    // Create date picker
    createDatePicker: (input, options = {}) => {
        const {
            format = 'dd/mm/yyyy',
            minDate = null,
            maxDate = null,
            onSelect = () => {}
        } = options;
        
        const picker = Utils.createElement('div', {
            className: 'datepicker',
            style: `
                position: relative;
                display: inline-block;
            `
        });
        
        const calendarContainer = Utils.createElement('div', {
            className: 'datepicker-calendar',
            style: `
                position: absolute;
                top: 100%;
                left: 0;
                margin-top: 4px;
                z-index: 1000;
                display: none;
            `
        });
        
        const toggleCalendar = () => {
            const isVisible = calendarContainer.style.display === 'block';
            calendarContainer.style.display = isVisible ? 'none' : 'block';
            
            if (!isVisible) {
                const calendar = Utils.createCalendar({
                    date: input.value ? new Date(input.value) : new Date(),
                    minDate,
                    maxDate,
                    onDateSelect: (date) => {
                        const formattedDate = Utils.formatDate(date, format);
                        input.value = formattedDate;
                        onSelect(date);
                        toggleCalendar();
                    }
                });
                
                calendarContainer.innerHTML = '';
                calendarContainer.appendChild(calendar);
            }
        };
        
        input.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleCalendar();
        });
        
        input.addEventListener('focus', toggleCalendar);
        
        document.addEventListener('click', (e) => {
            if (!picker.contains(e.target)) {
                calendarContainer.style.display = 'none';
            }
        });
        
        picker.appendChild(input);
        picker.appendChild(calendarContainer);
        
        return picker;
    },

    // Create time picker
    createTimePicker: (input, options = {}) => {
        const {
            format = '24h',
            interval = 30,
            onSelect = () => {}
        } = options;
        
        const picker = Utils.createElement('div', {
            className: 'timepicker',
            style: `
                position: relative;
                display: inline-block;
            `
        });
        
        const dropdown = Utils.createElement('div', {
            className: 'timepicker-dropdown',
            style: `
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                background: white;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                margin-top: 4px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                z-index: 1000;
                max-height: 200px;
                overflow-y: auto;
                display: none;
            `
        });
        
        const times = [];
        for (let hour = 0; hour < 24; hour++) {
            for (let minute = 0; minute < 60; minute += interval) {
                const time = new Date();
                time.setHours(hour, minute, 0, 0);
                
                let displayTime;
                if (format === '24h') {
                    displayTime = time.toLocaleTimeString('id-ID', { 
                        hour: '2-digit', 
                        minute: '2-digit',
                        hour12: false 
                    });
                } else {
                    displayTime = time.toLocaleTimeString('id-ID', { 
                        hour: '2-digit', 
                        minute: '2-digit'
                    });
                }
                
                times.push({
                    value: time.toTimeString().split(' ')[0],
                    display: displayTime
                });
            }
        }
        
        times.forEach(time => {
            const timeItem = Utils.createElement('div', {
                className: 'timepicker-item',
                'data-value': time.value,
                textContent: time.display,
                style: `
                    padding: 8px 16px;
                    cursor: pointer;
                    transition: background 0.2s;
                `
            });
            
            timeItem.addEventListener('click', () => {
                input.value = time.value;
                onSelect(time.value);
                dropdown.style.display = 'none';
            });
            
            timeItem.addEventListener('mouseenter', () => {
                timeItem.style.background = '#f8fafc';
            });
            
            timeItem.addEventListener('mouseleave', () => {
                timeItem.style.background = 'white';
            });
            
            dropdown.appendChild(timeItem);
        });
        
        const toggleDropdown = () => {
            dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
        };
        
        input.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleDropdown();
        });
        
        input.addEventListener('focus', toggleDropdown);
        
        document.addEventListener('click', (e) => {
            if (!picker.contains(e.target)) {
                dropdown.style.display = 'none';
            }
        });
        
        picker.appendChild(input);
        picker.appendChild(dropdown);
        
        return picker;
    },

    // Create color picker
    createColorPicker: (input, options = {}) => {
        const {
            colors = [
                '#667eea', '#764ba2', '#10b981', '#f59e0b', '#ef4444',
                '#3b82f6', '#8b5cf6', '#06b6d4', '#84cc16', '#f97316'
            ],
            onSelect = () => {}
        } = options;
        
        const picker = Utils.createElement('div', {
            className: 'colorpicker',
            style: `
                position: relative;
                display: inline-block;
            `
        });
        
        const preview = Utils.createElement('div', {
            className: 'colorpicker-preview',
            style: `
                width: 40px;
                height: 40px;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                cursor: pointer;
                background: ${input.value || '#667eea'};
            `
        });
        
        const dropdown = Utils.createElement('div', {
            className: 'colorpicker-dropdown',
            style: `
                position: absolute;
                top: 100%;
                left: 0;
                background: white;
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                margin-top: 4px;
                padding: 16px;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                z-index: 1000;
                display: none;
                grid-template-columns: repeat(5, 1fr);
                gap: 8px;
            `
        });
        
        colors.forEach(color => {
            const colorItem = Utils.createElement('div', {
                className: 'colorpicker-item',
                'data-color': color,
                style: `
                    width: 32px;
                    height: 32px;
                    border-radius: 6px;
                    background: ${color};
                    cursor: pointer;
                    transition: transform 0.2s;
                    border: 2px solid ${color === input.value ? '#1e293b' : 'transparent'};
                `
            });
            
            colorItem.addEventListener('click', () => {
                input.value = color;
                preview.style.background = color;
                onSelect(color);
                dropdown.style.display = 'none';
            });
            
            colorItem.addEventListener('mouseenter', () => {
                colorItem.style.transform = 'scale(1.1)';
            });
            
            colorItem.addEventListener('mouseleave', () => {
                colorItem.style.transform = 'scale(1)';
            });
            
            dropdown.appendChild(colorItem);
        });
        
        const customColor = Utils.createElement('input', {
            type: 'color',
            className: 'colorpicker-custom',
            value: input.value || '#667eea',
            style: `
                grid-column: 1 / -1;
                width: 100%;
                height: 40px;
                border: 2px solid #e2e8f0;
                border-radius: 6px;
                cursor: pointer;
            `
        });
        
        customColor.addEventListener('change', (e) => {
            const color = e.target.value;
            input.value = color;
            preview.style.background = color;
            onSelect(color);
        });
        
        dropdown.appendChild(customColor);
        
        const toggleDropdown = () => {
            dropdown.style.display = dropdown.style.display === 'grid' ? 'none' : 'grid';
        };
        
        preview.addEventListener('click', (e) => {
            e.stopPropagation();
            toggleDropdown();
        });
        
        document.addEventListener('click', (e) => {
            if (!picker.contains(e.target)) {
                dropdown.style.display = 'none';
            }
        });
        
        picker.appendChild(preview);
        picker.appendChild(dropdown);
        
        return picker;
    },

    // Create file upload
    createFileUpload: (options = {}) => {
        const {
            multiple = false,
            accept = '*/*',
            maxSize = 10, // MB
            onSelect = () => {},
            onError = () => {}
        } = options;
        
        const upload = Utils.createElement('div', {
            className: 'file-upload',
            style: `
                border: 2px dashed #e2e8f0;
                border-radius: 12px;
                padding: 40px 20px;
                text-align: center;
                cursor: pointer;
                transition: all 0.2s;
            `
        });
        
        const uploadIcon = Utils.createElement('div', {
            className: 'file-upload-icon',
            innerHTML: '<i class="fas fa-cloud-upload-alt"></i>',
            style: `
                font-size: 48px;
                color: #94a3b8;
                margin-bottom: 16px;
            `
        });
        
        const uploadText = Utils.createElement('div', {
            className: 'file-upload-text',
            textContent: 'Seret file atau klik untuk upload',
            style: `
                color: #64748b;
                font-weight: 600;
                margin-bottom: 8px;
            `
        });
        
        const uploadHint = Utils.createElement('div', {
            className: 'file-upload-hint',
            textContent: `Maksimal ${maxSize}MB per file`,
            style: `
                color: #94a3b8;
                font-size: 14px;
            `
        });
        
        const fileInput = Utils.createElement('input', {
            type: 'file',
            multiple,
            accept,
            style: `
                display: none;
            `
        });
        
        upload.appendChild(uploadIcon);
        upload.appendChild(uploadText);
        upload.appendChild(uploadHint);
        
        upload.addEventListener('click', () => {
            fileInput.click();
        });
        
        upload.addEventListener('dragover', (e) => {
            e.preventDefault();
            upload.style.borderColor = '#667eea';
            upload.style.background = '#f8fafc';
        });
        
        upload.addEventListener('dragleave', () => {
            upload.style.borderColor = '#e2e8f0';
            upload.style.background = 'white';
        });
        
        upload.addEventListener('drop', (e) => {
            e.preventDefault();
            upload.style.borderColor = '#e2e8f0';
            upload.style.background = 'white';
            
            const files = e.dataTransfer.files;
            handleFiles(files);
        });
        
        fileInput.addEventListener('change', (e) => {
            const files = e.target.files;
            handleFiles(files);
        });
        
        function handleFiles(files) {
            const validFiles = [];
            const errors = [];
            
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                
                if (file.size > maxSize * 1024 * 1024) {
                    errors.push(`File ${file.name} melebihi ukuran maksimal ${maxSize}MB`);
                    continue;
                }
                
                if (accept !== '*/*' && !accept.split(',').some(type => file.type.match(type.replace('*', '.*')))) {
                    errors.push(`File ${file.name} tidak sesuai format yang diizinkan`);
                    continue;
                }
                
                validFiles.push(file);
            }
            
            if (errors.length > 0) {
                onError(errors);
            }
            
            if (validFiles.length > 0) {
                onSelect(multiple ? validFiles : validFiles[0]);
            }
        }
        
        return {
            element: upload,
            input: fileInput,
            clear: () => {
                fileInput.value = '';
            }
        };
    },

    // Create progress bar
    createProgressBar: (options = {}) => {
        const {
            value = 0,
            max = 100,
            showLabel = true,
            size = 'md',
            color = '#667eea'
        } = options;
        
        const progressBar = Utils.createElement('div', {
            className: 'progress-bar',
            style: `
                display: flex;
                flex-direction: column;
                gap: 8px;
            `
        });
        
        const progressContainer = Utils.createElement('div', {
            className: 'progress-container',
            style: `
                height: ${size === 'sm' ? '4px' : size === 'lg' ? '12px' : '8px'};
                background: #e2e8f0;
                border-radius: 9999px;
                overflow: hidden;
            `
        });
        
        const progressFill = Utils.createElement('div', {
            className: 'progress-fill',
            style: `
                height: 100%;
                background: ${color};
                border-radius: 9999px;
                width: ${Math.min(100, (value / max) * 100)}%;
                transition: width 0.3s;
            `
        });
        
        progressContainer.appendChild(progressFill);
        progressBar.appendChild(progressContainer);
        
        if (showLabel) {
            const progressLabel = Utils.createElement('div', {
                className: 'progress-label',
                textContent: `${Math.round((value / max) * 100)}%`,
                style: `
                    text-align: right;
                    font-size: 14px;
                    color: #64748b;
                `
            });
            progressBar.appendChild(progressLabel);
        }
        
        return {
            element: progressBar,
            update: (newValue) => {
                const percentage = Math.min(100, (newValue / max) * 100);
                progressFill.style.width = percentage + '%';
                
                if (showLabel) {
                    progressBar.querySelector('.progress-label').textContent = `${Math.round(percentage)}%`;
                }
            }
        };
    },

    // Create rating stars
    createRating: (options = {}) => {
        const {
            value = 0,
            max = 5,
            readOnly = false,
            onRate = () => {}
        } = options;
        
        const rating = Utils.createElement('div', {
            className: 'rating',
            style: `
                display: inline-flex;
                gap: 4px;
            `
        });
        
        for (let i = 1; i <= max; i++) {
            const star = Utils.createElement('div', {
                className: 'rating-star',
                'data-value': i,
                innerHTML: i <= value ? '<i class="fas fa-star"></i>' : '<i class="far fa-star"></i>',
                style: `
                    color: ${i <= value ? '#f59e0b' : '#e2e8f0'};
                    cursor: ${readOnly ? 'default' : 'pointer'};
                    font-size: 24px;
                    transition: color 0.2s;
                `
            });
            
            if (!readOnly) {
                star.addEventListener('click', () => {
                    onRate(i);
                });
                
                star.addEventListener('mouseenter', () => {
                    rating.querySelectorAll('.rating-star').forEach((s, index) => {
                        s.style.color = index + 1 <= i ? '#f59e0b' : '#e2e8f0';
                    });
                });
                
                star.addEventListener('mouseleave', () => {
                    rating.querySelectorAll('.rating-star').forEach((s, index) => {
                        s.style.color = index + 1 <= value ? '#f59e0b' : '#e2e8f0';
                    });
                });
            }
            
            rating.appendChild(star);
        }
        
        return rating;
    },

    // Create toggle switch
    createToggle: (options = {}) => {
        const {
            checked = false,
            label = '',
            onToggle = () => {}
        } = options;
        
        const toggle = Utils.createElement('label', {
            className: 'toggle',
            style: `
                display: flex;
                align-items: center;
                gap: 12px;
                cursor: pointer;
            `
        });
        
        const toggleSwitch = Utils.createElement('div', {
            className: 'toggle-switch',
            style: `
                position: relative;
                width: 60px;
                height: 32px;
                background: ${checked ? '#667eea' : '#e2e8f0'};
                border-radius: 9999px;
                transition: background 0.2s;
            `
        });
        
        const toggleKnob = Utils.createElement('div', {
            className: 'toggle-knob',
            style: `
                position: absolute;
                top: 4px;
                left: ${checked ? '32px' : '4px'};
                width: 24px;
                height: 24px;
                background: white;
                border-radius: 50%;
                transition: left 0.2s;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            `
        });
        
        toggleSwitch.appendChild(toggleKnob);
        
        const toggleLabel = Utils.createElement('div', {
            className: 'toggle-label',
            textContent: label,
            style: `
                color: #1e293b;
                font-weight: 500;
            `
        });
        
        toggle.appendChild(toggleSwitch);
        toggle.appendChild(toggleLabel);
        
        toggle.addEventListener('click', () => {
            const newChecked = !checked;
            toggleSwitch.style.background = newChecked ? '#667eea' : '#e2e8f0';
            toggleKnob.style.left = newChecked ? '32px' : '4px';
            onToggle(newChecked);
        });
        
        return toggle;
    },

    // Create range slider
    createRangeSlider: (options = {}) => {
        const {
            min = 0,
            max = 100,
            value = 50,
            step = 1,
            showValue = true,
            onInput = () => {}
        } = options;
        
        const slider = Utils.createElement('div', {
            className: 'range-slider',
            style: `
                display: flex;
                flex-direction: column;
                gap: 12px;
            `
        });
        
        const sliderTrack = Utils.createElement('div', {
            className: 'slider-track',
            style: `
                position: relative;
                height: 6px;
                background: #e2e8f0;
                border-radius: 9999px;
            `
        });
        
        const sliderFill = Utils.createElement('div', {
            className: 'slider-fill',
            style: `
                position: absolute;
                height: 100%;
                background: #667eea;
                border-radius: 9999px;
                width: ${((value - min) / (max - min)) * 100}%;
            `
        });
        
        const sliderInput = Utils.createElement('input', {
            type: 'range',
            min,
            max,
            value,
            step,
            style: `
                position: absolute;
                top: 50%;
                left: 0;
                right: 0;
                transform: translateY(-50%);
                width: 100%;
                height: 20px;
                opacity: 0;
                cursor: pointer;
                z-index: 2;
            `
        });
        
        const sliderThumb = Utils.createElement('div', {
            className: 'slider-thumb',
            style: `
                position: absolute;
                top: 50%;
                left: ${((value - min) / (max - min)) * 100}%;
                transform: translate(-50%, -50%);
                width: 20px;
                height: 20px;
                background: white;
                border: 2px solid #667eea;
                border-radius: 50%;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                z-index: 1;
            `
        });
        
        sliderTrack.appendChild(sliderFill);
        sliderTrack.appendChild(sliderInput);
        sliderTrack.appendChild(sliderThumb);
        slider.appendChild(sliderTrack);
        
        if (showValue) {
            const sliderValue = Utils.createElement('div', {
                className: 'slider-value',
                textContent: value.toString(),
                style: `
                    text-align: center;
                    font-weight: 600;
                    color: #1e293b;
                `
            });
            slider.appendChild(sliderValue);
        }
        
        sliderInput.addEventListener('input', (e) => {
            const newValue = parseFloat(e.target.value);
            const percentage = ((newValue - min) / (max - min)) * 100;
            
            sliderFill.style.width = percentage + '%';
            sliderThumb.style.left = percentage + '%';
            
            if (showValue) {
                slider.querySelector('.slider-value').textContent = newValue.toString();
            }
            
            onInput(newValue);
        });
        
        return slider;
    },

    // Create stepper
    createStepper: (options = {}) => {
        const {
            value = 1,
            min = 1,
            max = 10,
            step = 1,
            onChange = () => {}
        } = options;
        
        const stepper = Utils.createElement('div', {
            className: 'stepper',
            style: `
                display: inline-flex;
                align-items: center;
                gap: 8px;
            `
        });
        
        const decrementButton = Utils.createElement('button', {
            className: 'stepper-button stepper-decrement',
            innerHTML: '<i class="fas fa-minus"></i>',
            disabled: value <= min,
            style: `
                width: 40px;
                height: 40px;
                border: 2px solid #e2e8f0;
                background: ${value <= min ? '#f8fafc' : 'white'};
                color: ${value <= min ? '#cbd5e1' : '#64748b'};
                border-radius: 8px;
                cursor: ${value <= min ? 'not-allowed' : 'pointer'};
                transition: all 0.2s;
                display: flex;
                align-items: center;
                justify-content: center;
            `
        });
        
        const valueDisplay = Utils.createElement('div', {
            className: 'stepper-value',
            textContent: value.toString(),
            style: `
                min-width: 60px;
                text-align: center;
                font-weight: 600;
                color: #1e293b;
                font-size: 18px;
            `
        });
        
        const incrementButton = Utils.createElement('button', {
            className: 'stepper-button stepper-increment',
            innerHTML: '<i class="fas fa-plus"></i>',
            disabled: value >= max,
            style: `
                width: 40px;
                height: 40px;
                border: 2px solid #e2e8f0;
                background: ${value >= max ? '#f8fafc' : 'white'};
                color: ${value >= max ? '#cbd5e1' : '#64748b'};
                border-radius: 8px;
                cursor: ${value >= max ? 'not-allowed' : 'pointer'};
                transition: all 0.2s;
                display: flex;
                align-items: center;
                justify-content: center;
            `
        });
        
        const updateButtons = () => {
            decrementButton.disabled = value <= min;
            decrementButton.style.background = value <= min ? '#f8fafc' : 'white';
            decrementButton.style.color = value <= min ? '#cbd5e1' : '#64748b';
            decrementButton.style.cursor = value <= min ? 'not-allowed' : 'pointer';
            
            incrementButton.disabled = value >= max;
            incrementButton.style.background = value >= max ? '#f8fafc' : 'white';
            incrementButton.style.color = value >= max ? '#cbd5e1' : '#64748b';
            incrementButton.style.cursor = value >= max ? 'not-allowed' : 'pointer';
        };
        
        decrementButton.addEventListener('click', () => {
            if (value > min) {
                const newValue = value - step;
                valueDisplay.textContent = newValue.toString();
                onChange(newValue);
                updateButtons();
            }
        });
        
        incrementButton.addEventListener('click', () => {
            if (value < max) {
                const newValue = value + step;
                valueDisplay.textContent = newValue.toString();
                onChange(newValue);
                updateButtons();
            }
        });
        
        stepper.appendChild(decrementButton);
        stepper.appendChild(valueDisplay);
        stepper.appendChild(incrementButton);
        
        updateButtons();
        
        return stepper;
    },

    // Create badge
    createBadge: (options = {}) => {
        const {
            text = '',
            type = 'default',
            size = 'md',
            rounded = false
        } = options;
        
        const typeStyles = {
            default: { background: '#e2e8f0', color: '#1e293b' },
            primary: { background: '#667eea', color: 'white' },
            success: { background: '#10b981', color: 'white' },
            warning: { background: '#f59e0b', color: 'white' },
            danger: { background: '#ef4444', color: 'white' }
        };
        
        const sizeStyles = {
            sm: { padding: '2px 8px', fontSize: '12px' },
            md: { padding: '4px 12px', fontSize: '14px' },
            lg: { padding: '6px 16px', fontSize: '16px' }
        };
        
        const badge = Utils.createElement('span', {
            className: `badge badge-${type}`,
            textContent: text,
            style: `
                display: inline-block;
                background: ${typeStyles[type].background};
                color: ${typeStyles[type].color};
                padding: ${sizeStyles[size].padding};
                font-size: ${sizeStyles[size].fontSize};
                font-weight: 600;
                border-radius: ${rounded ? '9999px' : '6px'};
                line-height: 1;
            `
        });
        
        return badge;
    },

    // Create avatar
    createAvatar: (options = {}) => {
        const {
            src = '',
            alt = '',
            size = 'md',
            shape = 'circle',
            initials = ''
        } = options;
        
        const sizeStyles = {
            sm: { width: '32px', height: '32px', fontSize: '12px' },
            md: { width: '48px', height: '48px', fontSize: '16px' },
            lg: { width: '64px', height: '64px', fontSize: '20px' },
            xl: { width: '96px', height: '96px', fontSize: '32px' }
        };
        
        const avatar = Utils.createElement('div', {
            className: 'avatar',
            style: `
                width: ${sizeStyles[size].width};
                height: ${sizeStyles[size].height};
                border-radius: ${shape === 'circle' ? '50%' : '12px'};
                background: linear-gradient(135deg, #667eea, #764ba2);
                display: flex;
                align-items: center;
                justify-content: center;
                color: white;
                font-weight: 600;
                font-size: ${sizeStyles[size].fontSize};
                overflow: hidden;
            `
        });
        
        if (src) {
            const img = Utils.createElement('img', {
                src,
                alt,
                style: `
                    width: 100%;
                    height: 100%;
                    object-fit: cover;
                `
            });
            avatar.appendChild(img);
        } else if (initials) {
            avatar.textContent = initials.substring(0, 2).toUpperCase();
        }
        
        return avatar;
    }
};

// Export utils
if (typeof module !== 'undefined' && module.exports) {
    module.exports = Utils;
} else {
    window.Utils = Utils;
}
