import os
import gradio as gr
import pandas as pd
import tempfile

def save_csv_to_temp(df: pd.DataFrame, prefix: str) -> str:
    """
    Save a DataFrame to a temporary CSV file.
    
    Args:
        df: DataFrame to save
        prefix: Prefix for the temporary file name
        
    Returns:
        Path to the saved temporary file
    """
    # Create a temporary file
    temp_dir = tempfile.gettempdir()
    temp_path = os.path.join(temp_dir, f"{prefix}_{pd.Timestamp.now().strftime('%Y%m%d_%H%M%S')}.csv")
    
    # Save the DataFrame to the temporary file
    df.to_csv(temp_path, index=False)
    
    return temp_path

def format_class_counts(class_counts: dict) -> str:
    """
    Format the class counts for display.
    
    Args:
        class_counts: Dictionary with counts of each class
        
    Returns:
        Formatted string with class counts
    """
    total = sum(class_counts.values())
    
    if total == 0:
        return "No records classified"
    
    result = f"Total records: {total}\n\n"
    
    for cls, count in class_counts.items():
        percentage = (count / total) * 100
        result += f"{cls.capitalize()}: {count} ({percentage:.2f}%)\n"
    
    return result

def get_theme() -> dict:
    """
    Define a custom theme for the Gradio app.
    
    Returns:
        Dictionary with theme configuration
    """
    return gr.themes.Default(
        primary_hue="blue",
        secondary_hue="indigo",
        neutral_hue="gray",
        radius_size="md",
        spacing_size="sm",
        font=[gr.themes.GoogleFont("Inter"), "sans-serif"],
        font_mono=[gr.themes.GoogleFont("IBM Plex Mono"), "monospace"]
    )
