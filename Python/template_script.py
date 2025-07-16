#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script Name: template_script.py
Description: Template for Python scripts with standard structure
Author: [Your Name]
Date: 2024-01-01
Version: 1.0
"""

import os
import sys
import logging
import argparse
from datetime import datetime
from typing import Optional, Dict, Any

# =============================================================================
# Configuration
# =============================================================================

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('script.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Colors for output (Windows compatible)
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    END = '\033[0m'

def print_color(message: str, color: str = Colors.END) -> None:
    """Print colored output to console."""
    print(f"{color}{message}{Colors.END}")

# =============================================================================
# Functions
# =============================================================================

def check_prerequisites() -> bool:
    """Check if all prerequisites are met."""
    logger.info("Checking prerequisites...")
    
    # Add your prerequisite checks here
    # Example: Check if required packages are installed
    # try:
    #     import required_package
    # except ImportError:
    #     logger.error("Required package 'required_package' is not installed")
    #     return False
    
    logger.info("✓ Prerequisites check passed")
    return True

def main_function(input_parameter: str) -> bool:
    """Main function containing the script logic."""
    try:
        logger.info(f"Processing: {input_parameter}")
        
        # Add your main logic here
        
        logger.info("Processing completed successfully!")
        return True
    except Exception as e:
        logger.error(f"Error in main_function: {str(e)}")
        return False

def validate_parameters(args: argparse.Namespace) -> bool:
    """Validate input parameters."""
    if not args.parameter_name:
        logger.error("Parameter name cannot be empty")
        return False
    return True

# =============================================================================
# Main Execution
# =============================================================================

def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="Template script with standard structure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python template_script.py --parameter-name "value"
  python template_script.py --verbose
        """
    )
    
    parser.add_argument(
        '--parameter-name',
        type=str,
        default='default_value',
        help='Description of the parameter'
    )
    
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        print_color(f"Script started at {datetime.now()}", Colors.CYAN)
        print_color("=" * 50, Colors.CYAN)
        
        # Check prerequisites
        if not check_prerequisites():
            return 1
        
        # Validate parameters
        if not validate_parameters(args):
            return 1
        
        # Execute main function
        if not main_function(args.parameter_name):
            return 1
        
        print_color("Script completed successfully!", Colors.GREEN)
        return 0
        
    except KeyboardInterrupt:
        logger.info("Script interrupted by user")
        return 1
    except Exception as e:
        logger.error(f"Script failed: {str(e)}")
        return 1
    finally:
        print_color(f"Script ended at {datetime.now()}", Colors.CYAN)

if __name__ == "__main__":
    sys.exit(main()) 