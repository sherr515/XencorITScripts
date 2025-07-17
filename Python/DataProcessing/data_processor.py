#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data Processor - Comprehensive Data Processing and Analysis

This script provides comprehensive data processing capabilities including:
- CSV, JSON, XML, Excel file processing
- Data cleaning and validation
- Data transformation and aggregation
- Statistical analysis and reporting
- Data visualization generation
- Database operations (SQLite, PostgreSQL, MySQL)
- Big data processing with pandas and numpy
- Machine learning data preparation
- Data export in multiple formats
- Batch processing and automation

Author: System Administrator
Version: 1.0.0
Date: 2024-01-01
"""

import os
import sys
import json
import logging
import argparse
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
import sqlite3
import psycopg2
import mysql.connector
from sqlalchemy import create_engine, text
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import xml.etree.ElementTree as ET
import yaml
import csv
import zipfile
import gzip
import pickle


class DataProcessor:
    """Comprehensive data processing system"""
    
    def __init__(self, config: Dict = None):
        """Initialize the data processor"""
        self.config = config or {}
        self.logger = self._setup_logging()
        
        # Setup database connections
        self._setup_database_connections()
        
        # Data storage
        self.data_cache = {}
        self.processed_data = {}
        
        # Visualization settings
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('DataProcessor')
        logger.setLevel(logging.INFO)
        
        # Create handlers
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler('data_processor.log')
        
        # Create formatters and add it to handlers
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(log_format)
        file_handler.setFormatter(log_format)
        
        # Add handlers to the logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    def _setup_database_connections(self):
        """Setup database connections"""
        self.db_connections = {}
        
        # SQLite connection
        if 'sqlite' in self.config:
            sqlite_config = self.config['sqlite']
            self.db_connections['sqlite'] = sqlite3.connect(sqlite_config['database'])
        
        # PostgreSQL connection
        if 'postgresql' in self.config:
            pg_config = self.config['postgresql']
            self.db_connections['postgresql'] = psycopg2.connect(
                host=pg_config['host'],
                port=pg_config['port'],
                database=pg_config['database'],
                user=pg_config['user'],
                password=pg_config['password']
            )
        
        # MySQL connection
        if 'mysql' in self.config:
            mysql_config = self.config['mysql']
            self.db_connections['mysql'] = mysql.connector.connect(
                host=mysql_config['host'],
                port=mysql_config['port'],
                database=mysql_config['database'],
                user=mysql_config['user'],
                password=mysql_config['password']
            )
    
    def load_csv(self, file_path: str, **kwargs) -> pd.DataFrame:
        """Load CSV file into DataFrame"""
        try:
            self.logger.info(f"Loading CSV file: {file_path}")
            df = pd.read_csv(file_path, **kwargs)
            self.logger.info(f"Loaded {len(df)} rows and {len(df.columns)} columns")
            return df
        except Exception as e:
            self.logger.error(f"Error loading CSV file {file_path}: {e}")
            return pd.DataFrame()
    
    def load_json(self, file_path: str, **kwargs) -> Union[pd.DataFrame, Dict]:
        """Load JSON file"""
        try:
            self.logger.info(f"Loading JSON file: {file_path}")
            
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # If data is a list of dictionaries, convert to DataFrame
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                df = pd.DataFrame(data)
                self.logger.info(f"Loaded {len(df)} rows and {len(df.columns)} columns")
                return df
            else:
                self.logger.info(f"Loaded JSON data with {len(data)} keys")
                return data
                
        except Exception as e:
            self.logger.error(f"Error loading JSON file {file_path}: {e}")
            return pd.DataFrame()
    
    def load_excel(self, file_path: str, sheet_name: str = None, **kwargs) -> pd.DataFrame:
        """Load Excel file into DataFrame"""
        try:
            self.logger.info(f"Loading Excel file: {file_path}")
            df = pd.read_excel(file_path, sheet_name=sheet_name, **kwargs)
            self.logger.info(f"Loaded {len(df)} rows and {len(df.columns)} columns")
            return df
        except Exception as e:
            self.logger.error(f"Error loading Excel file {file_path}: {e}")
            return pd.DataFrame()
    
    def load_xml(self, file_path: str) -> pd.DataFrame:
        """Load XML file into DataFrame"""
        try:
            self.logger.info(f"Loading XML file: {file_path}")
            
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Extract data from XML
            data = []
            for element in root.iter():
                if element.text and element.text.strip():
                    data.append({
                        'tag': element.tag,
                        'text': element.text.strip(),
                        'attributes': dict(element.attrib)
                    })
            
            df = pd.DataFrame(data)
            self.logger.info(f"Loaded {len(df)} XML elements")
            return df
            
        except Exception as e:
            self.logger.error(f"Error loading XML file {file_path}: {e}")
            return pd.DataFrame()
    
    def load_database(self, query: str, database: str = 'sqlite') -> pd.DataFrame:
        """Load data from database"""
        try:
            if database not in self.db_connections:
                raise ValueError(f"Database connection '{database}' not found")
            
            self.logger.info(f"Executing query on {database} database")
            df = pd.read_sql_query(query, self.db_connections[database])
            self.logger.info(f"Loaded {len(df)} rows and {len(df.columns)} columns")
            return df
            
        except Exception as e:
            self.logger.error(f"Error loading from database: {e}")
            return pd.DataFrame()
    
    def clean_data(self, df: pd.DataFrame, config: Dict = None) -> pd.DataFrame:
        """Clean and preprocess data"""
        try:
            self.logger.info("Starting data cleaning process")
            original_shape = df.shape
            
            # Remove duplicates
            if config.get('remove_duplicates', True):
                df = df.drop_duplicates()
                self.logger.info(f"Removed {original_shape[0] - len(df)} duplicate rows")
            
            # Handle missing values
            missing_strategy = config.get('missing_strategy', 'drop')
            if missing_strategy == 'drop':
                df = df.dropna()
            elif missing_strategy == 'fill':
                fill_values = config.get('fill_values', {})
                df = df.fillna(fill_values)
            
            # Remove outliers
            if config.get('remove_outliers', False):
                numeric_columns = df.select_dtypes(include=[np.number]).columns
                for col in numeric_columns:
                    Q1 = df[col].quantile(0.25)
                    Q3 = df[col].quantile(0.75)
                    IQR = Q3 - Q1
                    lower_bound = Q1 - 1.5 * IQR
                    upper_bound = Q3 + 1.5 * IQR
                    df = df[(df[col] >= lower_bound) & (df[col] <= upper_bound)]
            
            # Convert data types
            if config.get('convert_types', True):
                for col in df.columns:
                    # Try to convert to numeric
                    try:
                        df[col] = pd.to_numeric(df[col], errors='ignore')
                    except:
                        pass
                    
                    # Try to convert to datetime
                    try:
                        df[col] = pd.to_datetime(df[col], errors='ignore')
                    except:
                        pass
            
            self.logger.info(f"Data cleaning completed. Final shape: {df.shape}")
            return df
            
        except Exception as e:
            self.logger.error(f"Error cleaning data: {e}")
            return df
    
    def transform_data(self, df: pd.DataFrame, transformations: List[Dict]) -> pd.DataFrame:
        """Apply data transformations"""
        try:
            self.logger.info("Starting data transformation")
            
            for transform in transformations:
                transform_type = transform['type']
                
                if transform_type == 'rename':
                    df = df.rename(columns=transform['mapping'])
                
                elif transform_type == 'select':
                    df = df[transform['columns']]
                
                elif transform_type == 'filter':
                    condition = transform['condition']
                    df = df.query(condition)
                
                elif transform_type == 'groupby':
                    group_cols = transform['group_columns']
                    agg_funcs = transform['aggregations']
                    df = df.groupby(group_cols).agg(agg_funcs).reset_index()
                
                elif transform_type == 'sort':
                    df = df.sort_values(by=transform['columns'], ascending=transform.get('ascending', True))
                
                elif transform_type == 'add_column':
                    df[transform['column_name']] = transform['expression']
                
                elif transform_type == 'pivot':
                    df = df.pivot_table(
                        index=transform['index'],
                        columns=transform['columns'],
                        values=transform['values'],
                        aggfunc=transform.get('aggfunc', 'mean')
                    ).reset_index()
            
            self.logger.info("Data transformation completed")
            return df
            
        except Exception as e:
            self.logger.error(f"Error transforming data: {e}")
            return df
    
    def analyze_data(self, df: pd.DataFrame) -> Dict:
        """Perform comprehensive data analysis"""
        try:
            self.logger.info("Starting data analysis")
            
            analysis = {
                'basic_info': {
                    'shape': df.shape,
                    'columns': list(df.columns),
                    'dtypes': df.dtypes.to_dict(),
                    'memory_usage': df.memory_usage(deep=True).sum()
                },
                'missing_values': df.isnull().sum().to_dict(),
                'duplicates': df.duplicated().sum(),
                'numeric_summary': {},
                'categorical_summary': {},
                'correlations': {}
            }
            
            # Numeric columns analysis
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            if len(numeric_columns) > 0:
                analysis['numeric_summary'] = df[numeric_columns].describe().to_dict()
                
                # Correlation analysis
                if len(numeric_columns) > 1:
                    analysis['correlations'] = df[numeric_columns].corr().to_dict()
            
            # Categorical columns analysis
            categorical_columns = df.select_dtypes(include=['object', 'category']).columns
            for col in categorical_columns:
                analysis['categorical_summary'][col] = {
                    'unique_count': df[col].nunique(),
                    'top_values': df[col].value_counts().head(5).to_dict(),
                    'missing_count': df[col].isnull().sum()
                }
            
            self.logger.info("Data analysis completed")
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing data: {e}")
            return {}
    
    def create_visualizations(self, df: pd.DataFrame, config: Dict = None) -> Dict:
        """Create data visualizations"""
        try:
            self.logger.info("Creating visualizations")
            
            if not config:
                config = {}
            
            plots = {}
            output_dir = config.get('output_dir', 'plots')
            Path(output_dir).mkdir(exist_ok=True)
            
            # Distribution plots for numeric columns
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            for col in numeric_columns[:5]:  # Limit to first 5 columns
                plt.figure(figsize=(10, 6))
                plt.hist(df[col].dropna(), bins=30, alpha=0.7, edgecolor='black')
                plt.title(f'Distribution of {col}')
                plt.xlabel(col)
                plt.ylabel('Frequency')
                plt.tight_layout()
                
                plot_path = f"{output_dir}/distribution_{col}.png"
                plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                plt.close()
                plots[f'distribution_{col}'] = plot_path
            
            # Correlation heatmap
            if len(numeric_columns) > 1:
                plt.figure(figsize=(12, 10))
                correlation_matrix = df[numeric_columns].corr()
                sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm', center=0)
                plt.title('Correlation Heatmap')
                plt.tight_layout()
                
                plot_path = f"{output_dir}/correlation_heatmap.png"
                plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                plt.close()
                plots['correlation_heatmap'] = plot_path
            
            # Box plots for numeric columns
            if len(numeric_columns) > 0:
                plt.figure(figsize=(15, 8))
                df[numeric_columns].boxplot()
                plt.title('Box Plots of Numeric Variables')
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                plot_path = f"{output_dir}/box_plots.png"
                plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                plt.close()
                plots['box_plots'] = plot_path
            
            # Bar plots for categorical columns
            categorical_columns = df.select_dtypes(include=['object', 'category']).columns
            for col in categorical_columns[:3]:  # Limit to first 3 columns
                plt.figure(figsize=(12, 6))
                value_counts = df[col].value_counts().head(10)
                value_counts.plot(kind='bar')
                plt.title(f'Top 10 Values in {col}')
                plt.xlabel(col)
                plt.ylabel('Count')
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                plot_path = f"{output_dir}/bar_plot_{col}.png"
                plt.savefig(plot_path, dpi=300, bbox_inches='tight')
                plt.close()
                plots[f'bar_plot_{col}'] = plot_path
            
            self.logger.info(f"Created {len(plots)} visualizations")
            return plots
            
        except Exception as e:
            self.logger.error(f"Error creating visualizations: {e}")
            return {}
    
    def export_data(self, df: pd.DataFrame, output_path: str, format: str = 'csv') -> bool:
        """Export data to various formats"""
        try:
            self.logger.info(f"Exporting data to {output_path} in {format} format")
            
            if format.lower() == 'csv':
                df.to_csv(output_path, index=False)
            
            elif format.lower() == 'json':
                df.to_json(output_path, orient='records', indent=2)
            
            elif format.lower() == 'excel':
                df.to_excel(output_path, index=False)
            
            elif format.lower() == 'parquet':
                df.to_parquet(output_path, index=False)
            
            elif format.lower() == 'pickle':
                df.to_pickle(output_path)
            
            elif format.lower() == 'html':
                df.to_html(output_path, index=False)
            
            else:
                raise ValueError(f"Unsupported export format: {format}")
            
            self.logger.info(f"Data exported successfully to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
            return False
    
    def save_to_database(self, df: pd.DataFrame, table_name: str, database: str = 'sqlite', 
                        if_exists: str = 'replace') -> bool:
        """Save DataFrame to database"""
        try:
            if database not in self.db_connections:
                raise ValueError(f"Database connection '{database}' not found")
            
            self.logger.info(f"Saving data to {database} table: {table_name}")
            
            df.to_sql(table_name, self.db_connections[database], if_exists=if_exists, index=False)
            
            self.logger.info(f"Data saved successfully to {table_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving to database: {e}")
            return False
    
    def generate_report(self, df: pd.DataFrame, analysis: Dict, plots: Dict) -> Dict:
        """Generate comprehensive data report"""
        try:
            self.logger.info("Generating data report")
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'dataset_info': {
                    'name': 'Dataset Analysis Report',
                    'total_rows': len(df),
                    'total_columns': len(df.columns),
                    'memory_usage_mb': df.memory_usage(deep=True).sum() / 1024 / 1024
                },
                'data_quality': {
                    'missing_values': analysis.get('missing_values', {}),
                    'duplicate_rows': analysis.get('duplicates', 0),
                    'data_types': analysis.get('basic_info', {}).get('dtypes', {})
                },
                'statistical_summary': analysis.get('numeric_summary', {}),
                'categorical_analysis': analysis.get('categorical_summary', {}),
                'correlation_analysis': analysis.get('correlations', {}),
                'visualizations': list(plots.keys()),
                'recommendations': []
            }
            
            # Generate recommendations
            missing_pct = {col: (count / len(df)) * 100 for col, count in analysis.get('missing_values', {}).items()}
            high_missing = [col for col, pct in missing_pct.items() if pct > 50]
            
            if high_missing:
                report['recommendations'].append(f"Consider removing columns with high missing values: {high_missing}")
            
            if analysis.get('duplicates', 0) > 0:
                report['recommendations'].append("Consider removing duplicate rows")
            
            numeric_columns = df.select_dtypes(include=[np.number]).columns
            if len(numeric_columns) > 10:
                report['recommendations'].append("Consider feature selection for high-dimensional numeric data")
            
            self.logger.info("Data report generated successfully")
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return {}
    
    def process_pipeline(self, config: Dict) -> Dict:
        """Execute complete data processing pipeline"""
        try:
            self.logger.info("Starting data processing pipeline")
            
            # Load data
            input_config = config['input']
            if input_config['type'] == 'csv':
                df = self.load_csv(input_config['path'])
            elif input_config['type'] == 'json':
                df = self.load_json(input_config['path'])
            elif input_config['type'] == 'excel':
                df = self.load_excel(input_config['path'])
            elif input_config['type'] == 'xml':
                df = self.load_xml(input_config['path'])
            elif input_config['type'] == 'database':
                df = self.load_database(input_config['query'], input_config['database'])
            else:
                raise ValueError(f"Unsupported input type: {input_config['type']}")
            
            if df.empty:
                raise ValueError("No data loaded")
            
            # Clean data
            if 'cleaning' in config:
                df = self.clean_data(df, config['cleaning'])
            
            # Transform data
            if 'transformations' in config:
                df = self.transform_data(df, config['transformations'])
            
            # Analyze data
            analysis = self.analyze_data(df)
            
            # Create visualizations
            plots = {}
            if 'visualizations' in config:
                plots = self.create_visualizations(df, config['visualizations'])
            
            # Export data
            if 'output' in config:
                output_config = config['output']
                if output_config['type'] == 'file':
                    self.export_data(df, output_config['path'], output_config['format'])
                elif output_config['type'] == 'database':
                    self.save_to_database(df, output_config['table'], output_config['database'])
            
            # Generate report
            report = self.generate_report(df, analysis, plots)
            
            # Save report
            if 'report' in config:
                report_path = config['report']['path']
                with open(report_path, 'w') as f:
                    json.dump(report, f, indent=2)
            
            self.logger.info("Data processing pipeline completed successfully")
            return {
                'success': True,
                'data_shape': df.shape,
                'analysis': analysis,
                'plots': plots,
                'report': report
            }
            
        except Exception as e:
            self.logger.error(f"Error in data processing pipeline: {e}")
            return {'success': False, 'error': str(e)}


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Data Processor')
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--input', type=str, help='Input file path')
    parser.add_argument('--input-type', type=str, choices=['csv', 'json', 'excel', 'xml'], help='Input file type')
    parser.add_argument('--output', type=str, help='Output file path')
    parser.add_argument('--output-format', type=str, choices=['csv', 'json', 'excel', 'parquet'], help='Output format')
    parser.add_argument('--clean', action='store_true', help='Clean data')
    parser.add_argument('--analyze', action='store_true', help='Analyze data')
    parser.add_argument('--visualize', action='store_true', help='Create visualizations')
    parser.add_argument('--report', type=str, help='Generate report file')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Create data processor
    processor = DataProcessor(config)
    
    # Handle different operations
    if args.config:
        # Run complete pipeline
        result = processor.process_pipeline(config)
        print(json.dumps(result, indent=2))
    
    elif args.input:
        # Load and process single file
        if args.input_type == 'csv':
            df = processor.load_csv(args.input)
        elif args.input_type == 'json':
            df = processor.load_json(args.input)
        elif args.input_type == 'excel':
            df = processor.load_excel(args.input)
        elif args.input_type == 'xml':
            df = processor.load_xml(args.input)
        else:
            print("Error: --input-type is required when using --input")
            sys.exit(1)
        
        if args.clean:
            df = processor.clean_data(df)
        
        if args.analyze:
            analysis = processor.analyze_data(df)
            print(json.dumps(analysis, indent=2))
        
        if args.visualize:
            plots = processor.create_visualizations(df)
            print(f"Created {len(plots)} visualizations")
        
        if args.output:
            processor.export_data(df, args.output, args.output_format or 'csv')
        
        if args.report:
            analysis = processor.analyze_data(df)
            plots = processor.create_visualizations(df) if args.visualize else {}
            report = processor.generate_report(df, analysis, plots)
            with open(args.report, 'w') as f:
                json.dump(report, f, indent=2)
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 