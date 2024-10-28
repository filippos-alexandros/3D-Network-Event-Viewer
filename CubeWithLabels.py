from ursina import *


class CubeWithLabels(Entity):
    def __init__(self, text, **kwargs):
        super().__init__(
            **kwargs
        )

        # Create text entities for face of the cube
        self.label_front = Text(
            parent=self,
            text=text,
            origin=(0, 0),
            position=(0, 0, -0.5),
            color=color.red,
            scale=7,
            billboard=True  #Ensure text faces camera
        )

    def flash_text_white(self):
        #Change text color to white temporarily
        self.label_front.color = color.white
        #Revert to red after delay
        invoke(self.revert_text_color, delay=0.5)

    def revert_text_color(self):
        #Revert text to red
        self.label_front.color = color.red
