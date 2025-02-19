'''
This module defines reusable classes for the project's data visualization tasks.
'''
import os
import numpy as np
import pandas as pd
import seaborn as sbn
import scipy.stats as stats
import matplotlib.pyplot as plot
from typing import Tuple, List

class Plotter:
    '''A class for various plotting methods using matplotlib and Seaborn'''
    def __init__(
            self,
            style: str='whitegrid',
            figsize: Tuple[float, float]=(10, 6),
            palette: str='deep',
            context: str='notebook',
            font_scale: float=1.2,
            grid: bool=True,
            save_fig: bool=False,
            save_path: str='../plots'
        ) -> None:
        '''
        Initialize a graph plotter with customizable aesthetics.
        Args:
            style (str): The style of the grid.
            figsize (tuple): The size of the figure.
            palette (str): The color palette for plots.
            font_scale (float): The scale of the font size.
            grid (bool): The display of gridlines.
            save_fig (bool): Whether to save the figure to a file.
        '''
        sbn.set_style(style)
        sbn.set_palette(palette)
        sbn.set_context(context, font_scale=font_scale)
        self.figsize = figsize
        self.grid = grid
        self.save_fig = save_fig
        self.save_path = save_path

    def _save_plot(
            self,
            filename: str,
            path: str='../plots/',
            dpi: int=300) -> None:
        '''Saves the figure created with a Plotter class method.'''
        full_path = os.path.join(self.save_path, filename)
        if self.save_fig:
            plot.savefig(full_path, dpi=dpi)
            print(f'Plot saved: {full_path}')

    def _apply_transform(self, data: pd.Series, transform: str) -> pd.Series:
        '''
        Apply a transformation to a series of data.
        Args:
            data (pd.Series): A series to transform.
            transform (str): The type of transformation to apply.
        Returns: The transformed series.
        '''
        if transform == 'log':
            return data.apply(lambda x: np.log1p(x) if x > 0 else 0)
        elif transform == 'exp':
            return data.apply(np.exp)
        elif transform == 'sqrt':
            return data.apply(lambda x: np.sqrt(x) if x >= 0 else 0)
        else:
            print(
                f'Transformation type unknown: {transform}\nNo transformation applied to {data.name}.'
            )
            return data

    def plot_histogram(
            self,
            df: pd.DataFrame,
            column: str,
            title: str='',
            xlabel: str='',
            ylabel: str='Frequency',
            color: str='#0033cc',
            bins: int=30,
            alpha: float=0.8,
            xlim: Tuple[float, float]=None,
            ylim: Tuple[float, float]=None,
            xscale: str='linear',  # Options: 'linear', 'log', etc.
            yscale: str='linear',  # Options: 'linear', 'log', etc.
            transform: str=None,
            kde: bool=True,
            discrete: bool=False,
            xlabels: List[str]=None
        ) -> None:
        '''Plots a histogram with KDE and custom styling.'''
        plot.figure(figsize=self.figsize)

        df_copy = self._apply_transform(df[column].dropna(), transform)

        sbn.histplot(
            data=df_copy,
            kde=kde,
            bins=bins,
            color=color,
            alpha=alpha,
            edgecolor='black',
            discrete=discrete
        )

        plot.title(title, fontsize=14)
        plot.xlabel(xlabel, fontsize=12)
        plot.ylabel(ylabel, fontsize=12)
        plot.xscale(xscale)
        plot.yscale(yscale)

        if xlim:
            plot.xlim(xlim)
        if ylim:
            plot.ylim(ylim)
        if self.grid:
            plot.grid(axis='y', linestyle='--', alpha=0.7)

        # Customize x-axis labels if provided
        if xlabels:
            plot.xticks(ticks=range(len(xlabels)), labels=xlabels)

        self._save_plot(f"{title.replace(' ', '_').replace('-', '_').lower()}.png",)
        plot.show()

    def plot_qq(
            self,
            data: pd.DataFrame,
            column: str,
            title: str,
            dist: str='norm',
            color: str='blue',
            xlabel: str='',
            ylabel: str='Frequency',
            xlim: Tuple[float, float]=None,
            ylim: Tuple[float, float]=None,
            transform: str=None
        ) -> None:
        '''Creates a Q-Q plot to visually check for normal distribution.'''
        plot.figure(figsize=self.figsize)

        df_copy = self._apply_transform(data[column].dropna(), transform)

        stats.probplot(
            x=df_copy,
            dist=dist,
            fit=True,
            plot=plot
        )

        plot.title(title, fontsize=14)
        plot.xlabel(xlabel, fontsize=12)
        plot.ylabel(ylabel, fontsize=12)

        if xlim:
            plot.xlim(xlim)
        if ylim:
            plot.ylim(ylim)
        if self.grid:
            plot.grid(alpha=0.5, linestyle='--')

        plot.gca().get_lines()[1].set_color('red')  # Make reference line red
        plot.gca().get_lines()[0].set_markerfacecolor(color)  # Customize point color

        self._save_plot(f"{dist}_{title.replace(' ', '_').replace('-', '_').lower()}.png")
        plot.show()

    def plot_scatter(self,
            data: pd.DataFrame,
            x: str,
            y: str,
            title: str,
            xlabel: str,
            ylabel: str,
            color: str='dodgerblue',
            fit_color: str='red',
            alpha: float=0.7,
            fit_line: bool=True
        ) -> None:
        '''Creates a scatter plot to show relationships between two variables.'''
        plot.figure(figsize=self.figsize)

        sbn.scatterplot(x=x, y=y, data=data, color=color, alpha=alpha)

        if fit_line:
            sbn.regplot(x=x, y=y, data=data, color=fit_color, scatter=False)

        plot.title(title, fontsize=14)
        plot.xlabel(xlabel, fontsize=12)
        plot.ylabel(ylabel, fontsize=12)

        if self.grid:
            plot.grid(alpha=0.5, linestyle='--')

        self._save_plot(f"{title.replace(' ', '_').replace('-', '_').lower()}.png")
        plot.show()
